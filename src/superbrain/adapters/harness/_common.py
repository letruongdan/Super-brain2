"""Shared link-safe, fail-closed helpers and contracts for SP2-5 harness adapters."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import require_opaque_id, require_sha256_digest
from superbrain.ports.capture import (
    FORBIDDEN_CLIENT_CAPTURE_KEYS,
    CaptureEventRecord,
    ProducerCaptureGap,
)
from superbrain.ports.continuity import (
    ModelExchangeProof,
    RecipientProfile,
    SessionSegmentRecord,
)
from superbrain.ports.os import OsAdapters

_REPARSE_POINT = 0x400
_MAX_TEXT_FILE_BYTES = 1_048_576
_MAX_TRANSCRIPT_BYTES = 8 * 1024 * 1024


class AdapterCaptureStatus(StrEnum):
    """Fail-closed adapter capture / config inspection status (§8.2, matrix O2/O9)."""

    OK = "ok"
    UNKNOWN = "unknown"
    UNAVAILABLE = "unavailable"
    WORKSPACE_MISMATCH = "workspace_mismatch"


@dataclass(frozen=True)
class HarnessCaptureContext:
    """Trusted checkout/session binding supplied by the composition/daemon caller."""

    checkout_root: Path
    repo_id: str
    checkout_id: str
    producer_stream: str
    session_ref: str
    host_version: str | None = None
    expected_config_digest: str | None = None
    active_segment: SessionSegmentRecord | None = None
    bare_mode: bool = False
    hooks_enabled: bool = True

    def __post_init__(self) -> None:
        require_opaque_id(self.repo_id, label="repo_id")
        require_opaque_id(self.checkout_id, label="checkout_id")
        require_opaque_id(self.producer_stream, label="producer_stream")
        require_sha256_digest(self.session_ref)


@dataclass(frozen=True)
class HarnessConfigInspection:
    """Verified read-only snapshot of checkout-scoped harness configuration files."""

    harness_id: str
    checkout_root: Path
    hooks_configured: bool
    config_digest: str | None
    ask_commands_covered: bool
    present_files: tuple[str, ...]
    detail: str | None = None


@dataclass(frozen=True)
class AdaptedCaptureEvent:
    """Normalized capture record plus fail-closed recipient/segment provenance."""

    status: AdapterCaptureStatus
    record: CaptureEventRecord | ProducerCaptureGap | None
    recipient_profile: RecipientProfile
    channel_kind: str
    segment_changed: bool = False
    model_exchange: ModelExchangeProof | None = None
    reason: str | None = None


@dataclass(frozen=True)
class TranscriptReadResult:
    """Result of scoped transcript tail reading under ``allowed_roots``."""

    status: AdapterCaptureStatus
    events: tuple[AdaptedCaptureEvent, ...]
    skipped_out_of_scope: int = 0
    reason: str | None = None


def unknown_recipient_profile(harness_id: str = "unknown") -> RecipientProfile:
    """Default fail-closed ``RecipientProfile`` when any verified recipient field is absent."""
    return RecipientProfile(
        harness_id=harness_id if harness_id else "unknown",
        provider_endpoint_digest="unknown",
        model_config_digest="unknown",
        account_digest="unknown",
    )


def _is_link_or_reparse(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & _REPARSE_POINT)


def _has_unsafe_segment(path: Path, *, stop_at: Path | None = None) -> bool:
    raw = os.fspath(path)
    if not raw or "\x00" in raw or ".." in path.parts or not path.is_absolute():
        return True
    cur = path
    while True:
        if _is_link_or_reparse(cur):
            return True
        if stop_at is not None and cur == stop_at:
            break
        if cur.parent == cur:
            break
        cur = cur.parent
    return False


def verify_checkout_containment(observed_cwd: object, checkout_root: Path, os_: OsAdapters) -> bool:
    """Return ``True`` iff ``observed_cwd`` is safe and physically equal to or inside ``checkout_root``."""
    if not isinstance(observed_cwd, (str, Path)):
        return False
    raw = os.fspath(observed_cwd)
    if not raw or "\x00" in raw:
        return False
    try:
        os_.paths.reject_unsafe_path(raw)
        os_.paths.reject_unsafe_path(os.fspath(checkout_root))
    except BrainError:
        return False
    obs_path = Path(raw)
    if ".." in obs_path.parts or not obs_path.is_absolute() or not checkout_root.is_absolute():
        return False
    if _has_unsafe_segment(checkout_root) or _has_unsafe_segment(obs_path):
        return False
    try:
        chk_real = Path(os.path.realpath(checkout_root, strict=False))
        obs_real = Path(os.path.realpath(obs_path, strict=False))
    except OSError:
        return False
    if _is_link_or_reparse(chk_real) or _is_link_or_reparse(obs_real):
        return False
    return obs_real.is_relative_to(chk_real)


def read_safe_text_file(
    path: Path,
    os_: OsAdapters,
    *,
    max_bytes: int = _MAX_TEXT_FILE_BYTES,
    require_owner_only: bool = False,
) -> str | None:
    """Read regular UTF-8 file safely (no links/reparse points, bounded size); return ``None`` on error."""
    raw_str = os.fspath(path)
    if not raw_str or "\x00" in raw_str or ".." in path.parts or not path.is_absolute():
        return None
    try:
        os_.paths.reject_unsafe_path(raw_str)
        os_.paths.reject_links(path)
    except BrainError:
        return None
    if _has_unsafe_segment(path) or not os.path.lexists(path):
        return None
    try:
        pre_st = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISREG(pre_st.st_mode) or pre_st.st_size > max_bytes:
        return None
    if require_owner_only:
        try:
            if os_.permissions.check_ancestors(path) or os_.permissions.object_problems(path):
                return None
        except BrainError:
            return None
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode) or fst.st_size > max_bytes or not os.path.samestat(pre_st, fst):
            return None
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(fd, 65_536):
            total += len(chunk)
            if total > max_bytes:
                return None
            chunks.append(chunk)
        post_st = os.lstat(path)
        if not os.path.samestat(fst, post_st):
            return None
        return b"".join(chunks).decode("utf-8", errors="strict")
    except (OSError, UnicodeDecodeError):
        return None
    finally:
        os.close(fd)


def _digest_field(raw: Mapping[str, object], digest_key: str, plain_key: str) -> str:
    dval = raw.get(digest_key)
    if isinstance(dval, str):
        try:
            require_sha256_digest(dval)
            return dval
        except BrainError:
            return "unknown"
    pval = raw.get(plain_key)
    if isinstance(pval, str) and pval.strip():
        return digest_bytes(pval.strip().encode("utf-8"))
    return "unknown"


def extract_recipient_profile(harness_id: str, raw_event: Mapping[str, object]) -> RecipientProfile:
    """Build a canonical-digest ``RecipientProfile``, defaulting missing fields to ``'unknown'``."""
    rec_raw = raw_event.get("recipient")
    src = rec_raw if isinstance(rec_raw, Mapping) else raw_event
    return RecipientProfile(
        harness_id=harness_id,
        provider_endpoint_digest=_digest_field(src, "provider_endpoint_digest", "provider_endpoint"),
        model_config_digest=_digest_field(src, "model_config_digest", "model_config"),
        account_digest=_digest_field(src, "account_digest", "account_id"),
    )


def strip_forbidden_client_keys(value: object) -> JsonValue:
    """Recursively drop client-forged authority/session keys so adapters never emit them."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        out: dict[str, JsonValue] = {}
        for k, v in value.items():
            if not isinstance(k, str) or k in FORBIDDEN_CLIENT_CAPTURE_KEYS:
                continue
            out[k] = strip_forbidden_client_keys(v)
        return out
    if isinstance(value, (list, tuple)):
        return [strip_forbidden_client_keys(item) for item in value]
    raise BrainError(ErrorCode.INVALID_INPUT, "unsupported JSON payload type")


def compute_checkout_config_digest(
    *,
    harness_id: str,
    checkout_root: Path,
    os_: OsAdapters,
) -> tuple[str | None, tuple[str, ...], bool, bool]:
    """Read harness checkout files safely and return ``(digest, files, hooks_ok, ask_covered)``."""
    from superbrain.adapters.harness_config.bootstrap_templates import AUTHORITY_ASK_COMMANDS

    present: list[str] = []
    if harness_id == "claude-code":
        settings_rel = ".claude/settings.local.json"
        settings_text = read_safe_text_file(checkout_root / ".claude" / "settings.local.json", os_)
        if settings_text is None:
            settings_rel = ".claude/settings.json"
            settings_text = read_safe_text_file(checkout_root / ".claude" / "settings.json", os_)
        for rel, sub in ((".mcp.json", (".mcp.json",)), ("CLAUDE.md", ("CLAUDE.md",))):
            if read_safe_text_file(checkout_root.joinpath(*sub), os_) is not None:
                present.append(rel)
        if settings_text is None:
            return None, tuple(present), False, False
        present.append(settings_rel)
        try:
            parsed = json_loads_mapping(settings_text)
        except ValueError:
            return None, tuple(present), False, False
        cfg_dig = digest_bytes(canonical_json(parsed))
        hooks = parsed.get("hooks")
        hooks_ok = isinstance(hooks, Mapping) and bool(hooks)
        perms = parsed.get("permissions")
        ask_list = perms.get("ask") if isinstance(perms, Mapping) else None
        ask_covered = isinstance(ask_list, list) and all(
            any(isinstance(entry, str) and cmd in entry for entry in ask_list)
            for cmd in AUTHORITY_ASK_COMMANDS
        )
        return cfg_dig, tuple(present), hooks_ok, ask_covered

    if harness_id == "codex":
        hooks_text = read_safe_text_file(checkout_root / ".codex" / "hooks.json", os_)
        toml_text = read_safe_text_file(checkout_root / ".codex" / "config.toml", os_)
        if read_safe_text_file(checkout_root / "AGENTS.md", os_) is not None:
            present.append("AGENTS.md")
        if toml_text is not None:
            present.append(".codex/config.toml")
        if hooks_text is not None:
            present.append(".codex/hooks.json")
        if hooks_text is None and toml_text is None:
            return None, tuple(present), False, False
        hooks_obj: JsonValue | None = None
        hooks_ok = False
        ask_covered = False
        if hooks_text is not None:
            try:
                parsed_hooks = json_loads_mapping(hooks_text)
            except ValueError:
                return None, tuple(present), False, False
            hooks_obj = parsed_hooks
            h_sec = parsed_hooks.get("hooks")
            hooks_ok = isinstance(h_sec, Mapping) and bool(h_sec)
        payload_obj: dict[str, JsonValue] = {}
        if hooks_obj is not None:
            payload_obj["hooks"] = hooks_obj
        if toml_text is not None:
            payload_obj["config_toml"] = toml_text
        return digest_bytes(canonical_json(payload_obj)), tuple(present), hooks_ok, ask_covered

    return None, (), False, False


def json_loads_mapping(text: str) -> dict[str, JsonValue]:
    import json

    decoded = json.loads(text)
    if not isinstance(decoded, dict):
        raise ValueError("expected JSON object")
    stripped = strip_forbidden_client_keys(decoded)
    assert isinstance(stripped, dict)
    return stripped


def adapt_harness_event(
    raw_event: Mapping[str, object],
    *,
    harness_id: str,
    context: HarnessCaptureContext,
    event_kind_map: Mapping[str, str],
    os_: OsAdapters,
    inspect_fn: HarnessConfigInspection | None = None,
) -> AdaptedCaptureEvent:
    """Adapt one raw harness hook/transcript entry into a verified ``AdaptedCaptureEvent``."""
    fail_prof = unknown_recipient_profile(harness_id)
    if context.bare_mode or not context.hooks_enabled:
        return AdaptedCaptureEvent(
            AdapterCaptureStatus.UNAVAILABLE, None, fail_prof, "unknown", reason="hooks_disabled"
        )
    if not isinstance(raw_event, Mapping):
        return AdaptedCaptureEvent(
            AdapterCaptureStatus.UNKNOWN, None, fail_prof, "unknown", reason="invalid_event_object"
        )
    cwd_raw = raw_event.get("cwd")
    if cwd_raw is None:
        return AdaptedCaptureEvent(AdapterCaptureStatus.UNKNOWN, None, fail_prof, "unknown", reason="missing_cwd")
    if not verify_checkout_containment(cwd_raw, context.checkout_root, os_):
        return AdaptedCaptureEvent(
            AdapterCaptureStatus.WORKSPACE_MISMATCH, None, fail_prof, "unknown", reason="checkout_mismatch"
        )

    eff_cfg_digest = context.expected_config_digest
    if eff_cfg_digest is None and inspect_fn is not None:
        eff_cfg_digest = inspect_fn.config_digest

    source_meta: dict[str, JsonValue] = {}
    if context.host_version is not None:
        source_meta["host_version"] = context.host_version
    if eff_cfg_digest is not None:
        source_meta["config_digest"] = eff_cfg_digest

    if raw_event.get("record_kind") == "capture_gap":
        raw_seq = raw_event.get("sequence")
        seq_val = raw_seq if type(raw_seq) is int else 0
        raw_est = raw_event.get("estimated_count")
        est_val = raw_est if type(raw_est) is int else 1
        raw_dur = raw_event.get("duration_ms")
        dur_val = raw_dur if type(raw_dur) is int else None
        try:
            gap = ProducerCaptureGap(
                gap_id=str(raw_event.get("gap_id", "")),
                producer_stream=context.producer_stream,
                sequence=seq_val,
                reason=str(raw_event.get("reason", "")),
                recorded_at=str(raw_event.get("recorded_at", "")),
                estimated_count=est_val,
                duration_ms=dur_val,
            )
        except BrainError:
            return AdaptedCaptureEvent(
                AdapterCaptureStatus.UNKNOWN, None, fail_prof, "unknown", reason="invalid_gap"
            )
        return AdaptedCaptureEvent(AdapterCaptureStatus.OK, gap, fail_prof, "local_capture")

    raw_name = raw_event.get("event_name") or raw_event.get("kind")
    if not isinstance(raw_name, str) or raw_name not in event_kind_map:
        return AdaptedCaptureEvent(
            AdapterCaptureStatus.UNAVAILABLE, None, fail_prof, "unknown", reason="unsupported_event"
        )
    mapped_kind = event_kind_map[raw_name]

    ev_sess = raw_event.get("session_ref")
    if isinstance(ev_sess, str) and ev_sess != context.session_ref:
        return AdaptedCaptureEvent(
            AdapterCaptureStatus.WORKSPACE_MISMATCH, None, fail_prof, "unknown", reason="session_mismatch"
        )

    raw_payload = raw_event.get("payload")
    if not isinstance(raw_payload, Mapping):
        return AdaptedCaptureEvent(
            AdapterCaptureStatus.UNKNOWN, None, fail_prof, "unknown", reason="missing_payload"
        )
    clean_payload = strip_forbidden_client_keys(raw_payload)
    assert isinstance(clean_payload, dict)

    raw_ev_seq = raw_event.get("sequence")
    ev_seq = raw_ev_seq if type(raw_ev_seq) is int else 0
    try:
        normalized = CaptureEventRecord(
            event_id=str(raw_event.get("event_id", "")),
            producer_stream=context.producer_stream,
            sequence=ev_seq,
            harness_id=harness_id,
            kind=mapped_kind,
            recorded_at=str(raw_event.get("recorded_at", "")),
            payload=clean_payload,
            session_ref=context.session_ref,
            source_metadata=source_meta,
        )
    except BrainError:
        return AdaptedCaptureEvent(
            AdapterCaptureStatus.UNKNOWN, None, fail_prof, "unknown", reason="invalid_event_fields"
        )

    profile = extract_recipient_profile(harness_id, raw_event)
    seg_changed = (
        context.active_segment is None
        or context.active_segment.profile.segment_key() != profile.segment_key()
    )
    raw_ch = raw_event.get("channel_kind")
    ch_kind = raw_ch if isinstance(raw_ch, str) and raw_ch in ("local_capture", "model_io") else "unknown"

    exchange: ModelExchangeProof | None = None
    mc = raw_event.get("model_call")
    if (
        ch_kind == "model_io"
        and profile.is_complete
        and isinstance(mc, Mapping)
        and mc.get("completed") is True
        and isinstance(mc.get("id"), str)
        and mc["id"].strip()
    ):
        if context.active_segment is not None and not seg_changed:
            seg_id = context.active_segment.segment_id
        else:
            seg_dig = digest_bytes(canonical_json(list(profile.segment_key())))
            seg_id = f"seg-{seg_dig[7:19]}"
        item_dig = digest_bytes(canonical_json(normalized.payload))
        exchange = ModelExchangeProof(
            item_digest=item_dig,
            segment_id=seg_id,
            completed_model_call_id=mc["id"].strip(),
            completed=True,
            recipient_profile=profile,
        )

    return AdaptedCaptureEvent(
        status=AdapterCaptureStatus.OK,
        record=normalized,
        recipient_profile=profile,
        channel_kind=ch_kind,
        segment_changed=seg_changed,
        model_exchange=exchange,
    )


def read_scoped_transcript_file(
    transcript_path: Path,
    *,
    harness_id: str,
    context: HarnessCaptureContext,
    allowed_roots: Sequence[Path],
    event_kind_map: Mapping[str, str],
    os_: OsAdapters,
    inspect_fn: HarnessConfigInspection | None = None,
    start_sequence: int = 1,
) -> TranscriptReadResult:
    """Safely read a JSONL transcript strictly within ``allowed_roots``, filtering checkout & session."""
    import json

    if not allowed_roots or not isinstance(transcript_path, Path):
        return TranscriptReadResult(AdapterCaptureStatus.UNAVAILABLE, (), reason="no_allowed_roots")
    raw_tr = os.fspath(transcript_path)
    if not raw_tr or "\x00" in raw_tr or ".." in transcript_path.parts or not transcript_path.is_absolute():
        return TranscriptReadResult(AdapterCaptureStatus.UNAVAILABLE, (), reason="unsafe_transcript_path")
    try:
        os_.paths.reject_unsafe_path(raw_tr)
        os_.paths.reject_links(transcript_path)
    except BrainError:
        return TranscriptReadResult(AdapterCaptureStatus.UNAVAILABLE, (), reason="unsafe_transcript_path")

    if _has_unsafe_segment(transcript_path):
        return TranscriptReadResult(AdapterCaptureStatus.UNAVAILABLE, (), reason="symlink_or_reparse")
    try:
        tr_real = Path(os.path.realpath(transcript_path, strict=False))
    except OSError:
        return TranscriptReadResult(AdapterCaptureStatus.UNAVAILABLE, (), reason="realpath_failed")

    root_ok = False
    for root in allowed_roots:
        if not root.is_absolute() or _has_unsafe_segment(root):
            continue
        try:
            r_real = Path(os.path.realpath(root, strict=False))
        except OSError:
            continue
        if tr_real.is_relative_to(r_real):
            root_ok = True
            break
    if not root_ok:
        return TranscriptReadResult(AdapterCaptureStatus.UNAVAILABLE, (), reason="outside_allowed_roots")

    text = read_safe_text_file(
        transcript_path, os_, max_bytes=_MAX_TRANSCRIPT_BYTES, require_owner_only=True
    )
    if text is None:
        return TranscriptReadResult(AdapterCaptureStatus.UNAVAILABLE, (), reason="unreadable_transcript")

    events: list[AdaptedCaptureEvent] = []
    skipped = 0
    seq = start_sequence
    cur_ctx = context
    for line in text.splitlines():
        stripped_line = line.strip()
        if not stripped_line:
            continue
        try:
            raw_obj = json.loads(stripped_line)
        except ValueError:
            skipped += 1
            continue
        if not isinstance(raw_obj, dict):
            skipped += 1
            continue
        entry = dict(raw_obj)
        entry.setdefault("sequence", seq)
        adapted = adapt_harness_event(
            entry,
            harness_id=harness_id,
            context=cur_ctx,
            event_kind_map=event_kind_map,
            os_=os_,
            inspect_fn=inspect_fn,
        )
        if adapted.status is not AdapterCaptureStatus.OK or adapted.record is None:
            skipped += 1
            continue
        events.append(adapted)
        seq += 1
        if adapted.segment_changed and isinstance(adapted.record, CaptureEventRecord):
            next_seg = SessionSegmentRecord(
                segment_id=f"seg-{digest_bytes(canonical_json(list(adapted.recipient_profile.segment_key())))[7:19]}",
                session_ref=cur_ctx.session_ref,
                segment_index=(cur_ctx.active_segment.segment_index + 1) if cur_ctx.active_segment else 1,
                profile=adapted.recipient_profile,
                opened_at=adapted.record.recorded_at,
            )
            cur_ctx = HarnessCaptureContext(
                checkout_root=cur_ctx.checkout_root,
                repo_id=cur_ctx.repo_id,
                checkout_id=cur_ctx.checkout_id,
                producer_stream=cur_ctx.producer_stream,
                session_ref=cur_ctx.session_ref,
                host_version=cur_ctx.host_version,
                expected_config_digest=cur_ctx.expected_config_digest,
                active_segment=next_seg,
                bare_mode=cur_ctx.bare_mode,
                hooks_enabled=cur_ctx.hooks_enabled,
            )
    return TranscriptReadResult(AdapterCaptureStatus.OK, tuple(events), skipped_out_of_scope=skipped)
