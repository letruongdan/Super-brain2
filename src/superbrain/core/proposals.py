"""Pure proposal, journal, managed-slice models and Q25 path guards (spec 5.8, 8.11, 11.2).

Stdlib + ``superbrain.core`` only: no filesystem I/O, no platform inspection.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from superbrain.core._kernel_approval import RiskLevel, RiskResource, TargetFile
from superbrain.core._kernel_base import (
    ResourceDigest,
    is_strict_int,
    require_opaque_id,
    require_sha256_digest,
)
from superbrain.core.errors import BrainError, ErrorCode

__all__ = [
    "ApplyJournal",
    "ChangeProposal",
    "FileJournalEntry",
    "FileJournalPhase",
    "FileOriginalState",
    "JournalDirection",
    "ManagedFormat",
    "ManagedSliceManifest",
    "ProposalStatus",
    "ProposalTarget",
    "assert_not_skill_or_internal_target",
    "normalize_proposal_rel_path",
    "validate_journal_id",
]

_FORBIDDEN_SEGMENT_PREFIXES: tuple[tuple[str, ...], ...] = (
    (".claude", "skills"),
    (".codex", "skills"),
    (".agents", "skills"),
    (".gemini", "skills"),
    (".gemini", "antigravity", "skills"),
    (".gemini", "config", "skills"),
    (".git",),
)


class ProposalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    APPLYING = "applying"
    PARTIALLY_APPLIED = "partially_applied"
    APPLIED = "applied"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    RECOVERY_REQUIRED = "recovery_required"


class JournalDirection(StrEnum):
    APPLY = "apply"
    ROLLBACK = "rollback"


class FileOriginalState(StrEnum):
    PRESENT = "present"
    ABSENT = "absent"


class FileJournalPhase(StrEnum):
    PLANNED = "planned"
    ORIGINAL_MOVED = "original_moved"
    REPLACEMENT_PUBLISHED = "replacement_published"
    RESTORED = "restored"
    DELETED = "deleted"
    CONFLICT = "conflict"


class ManagedFormat(StrEnum):
    MARKDOWN = "markdown"
    JSON = "json"
    TOML = "toml"
    RAW = "raw"


def _unsafe(message: str = "unsafe path") -> BrainError:
    return BrainError(ErrorCode.UNSAFE_PATH, message)


def _invalid(message: str = "invalid input") -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, message)


_WIN32_RESERVED_DEVICES: frozenset[str] = frozenset(
    {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{i}" for i in range(1, 10)),
        *(f"lpt{i}" for i in range(1, 10)),
    }
)


def _validate_path_segment(seg: str) -> None:
    if seg in ("", ".", ".."):
        raise _unsafe()
    if any(ord(ch) < 0x20 for ch in seg):
        raise _unsafe()
    if seg != seg.strip(" \t\r\n") or seg.endswith("."):
        raise _unsafe()
    stem = seg.rstrip(". ").split(".", 1)[0].casefold()
    if stem in _WIN32_RESERVED_DEVICES:
        raise _unsafe()


def normalize_proposal_rel_path(rel_path: str) -> str:
    """Normalize a checkout-relative target path to POSIX ``/`` form, refusing escapes/UNC/device/ADS."""
    if not isinstance(rel_path, str) or not rel_path or "\x00" in rel_path or any(ord(c) < 0x20 for c in rel_path):
        raise _invalid()
    if rel_path.startswith(("\\\\", "//", "/", "\\")) or ":" in rel_path:
        raise _unsafe()
    parts = rel_path.replace("\\", "/").split("/")
    for seg in parts:
        _validate_path_segment(seg)
    return "/".join(parts)


def validate_journal_id(journal_id: str) -> str:
    """Validate an opaque single-segment ``journal_id`` safe for staging directory names."""
    if (
        not isinstance(journal_id, str)
        or not journal_id
        or "\x00" in journal_id
        or any(ord(c) < 0x20 for c in journal_id)
    ):
        raise _invalid()
    if "/" in journal_id or "\\" in journal_id or ":" in journal_id or any(c.isspace() for c in journal_id):
        raise _invalid()
    _validate_path_segment(journal_id)
    return journal_id


def _collapse_path_tokens(raw: str, *, require_absolute: bool = False) -> tuple[str, tuple[str, ...]]:
    """Pure lexical path decomposition ``(casefolded_anchor, casefolded_segments)`` rejecting UNC/device/ADS."""
    if not isinstance(raw, str) or not raw or "\x00" in raw or any(ord(c) < 0x20 for c in raw):
        raise _invalid()
    if raw.startswith(("\\\\", "//")):
        raise _unsafe()
    drive_colon = 1 if len(raw) >= 2 and raw[0].isalpha() and raw[1] == ":" else -1
    if any(i != drive_colon for i, ch in enumerate(raw) if ch == ":"):
        raise _unsafe()
    unix_like = raw.replace("\\", "/")
    anchor = ""
    rest = unix_like
    if drive_colon == 1:
        if len(unix_like) < 3 or unix_like[2] != "/":
            raise _unsafe()
        anchor = unix_like[:2].casefold()
        rest = unix_like[3:]
    elif unix_like.startswith("/"):
        anchor = "/"
        rest = unix_like[1:]
    if require_absolute and not anchor:
        raise _unsafe("path must be absolute")
    stack: list[str] = []
    for seg in rest.split("/"):
        if not seg or seg == ".":
            continue
        if seg == "..":
            if not stack:
                if not anchor:
                    raise _unsafe()
                continue
            stack.pop()
            continue
        _validate_path_segment(seg)
        stack.append(seg.casefold())
    return anchor, tuple(stack)


def _contains_segment_subsequence(parts: tuple[str, ...], seq: tuple[str, ...]) -> bool:
    n = len(seq)
    return any(parts[i : i + n] == seq for i in range(len(parts) - n + 1))


def assert_not_skill_or_internal_target(
    target_root: str,
    rel_path: str,
    *,
    data_root: str | None = None,
    home_dir: str | None = None,
) -> str:
    """Enforce Q25 skill-dir ban and internal ``data_root`` / ``.git`` ban; return normalized relative path."""
    norm_rel = normalize_proposal_rel_path(rel_path)
    root_anchor, root_parts = _collapse_path_tokens(target_root, require_absolute=True)
    rel_parts = tuple(seg.casefold() for seg in norm_rel.split("/"))
    full_parts = (*root_parts, *rel_parts)

    for forbidden in _FORBIDDEN_SEGMENT_PREFIXES:
        if _contains_segment_subsequence(full_parts, forbidden):
            raise _unsafe("target resolves inside a forbidden skill or internal directory")

    if data_root is not None:
        data_anchor, data_parts = _collapse_path_tokens(data_root, require_absolute=True)
        if root_anchor == data_anchor and full_parts[: len(data_parts)] == data_parts:
            raise _unsafe("target resolves inside data_root")

    if home_dir is not None:
        home_anchor, home_parts = _collapse_path_tokens(home_dir, require_absolute=True)
        if root_anchor == home_anchor and full_parts[: len(home_parts)] == home_parts:
            tail = full_parts[len(home_parts) :]
            for forbidden in _FORBIDDEN_SEGMENT_PREFIXES:
                if len(tail) >= len(forbidden) and tail[: len(forbidden)] == forbidden:
                    raise _unsafe("target resolves inside a user skill directory")

    return norm_rel


@dataclass(frozen=True)
class ProposalTarget:
    rel_path: str
    normalized_rel_path: str
    managed_format: ManagedFormat
    slice_id: str
    base_present: bool
    base_digest: str | None
    base_physical_id: str | None
    replacement_digest: str | None
    managed_slice_digest: str | None = None
    target_root: str = ""
    parent_physical_id: str = ""

    def __post_init__(self) -> None:
        if normalize_proposal_rel_path(self.rel_path) != self.normalized_rel_path:
            raise _invalid()
        if not isinstance(self.managed_format, ManagedFormat):
            raise _invalid()
        if not isinstance(self.slice_id, str) or not self.slice_id or "\x00" in self.slice_id:
            raise _invalid()
        if not isinstance(self.base_present, bool):
            raise _invalid()
        if self.base_present:
            require_sha256_digest(self.base_digest)
            if not isinstance(self.base_physical_id, str) or not self.base_physical_id:
                raise _invalid()
        elif self.base_digest is not None or self.base_physical_id is not None:
            raise _invalid()
        if self.replacement_digest is not None:
            require_sha256_digest(self.replacement_digest)
        if self.managed_slice_digest is not None:
            require_sha256_digest(self.managed_slice_digest)

    def to_target_file(self) -> TargetFile:
        return TargetFile(
            root_path=self.target_root,
            normalized_rel_path=self.normalized_rel_path,
            parent_physical_id=self.parent_physical_id,
            target_physical_id=self.base_physical_id if self.base_present else None,
            original_digest=self.base_digest if self.base_present else None,
            original_present=self.base_present,
        )


@dataclass(frozen=True)
class ManagedSliceManifest:
    proposal_id: str
    normalized_rel_path: str
    managed_format: ManagedFormat
    slice_id: str
    slice_digest: str
    full_file_digest: str
    updated_at: str
    target_root: str = ""

    def __post_init__(self) -> None:
        require_opaque_id(self.proposal_id)
        normalize_proposal_rel_path(self.normalized_rel_path)
        if not isinstance(self.managed_format, ManagedFormat):
            raise _invalid()
        if not isinstance(self.slice_id, str) or not self.slice_id:
            raise _invalid()
        if not isinstance(self.target_root, str) or "\x00" in self.target_root:
            raise _invalid()
        require_sha256_digest(self.slice_digest)
        require_sha256_digest(self.full_file_digest)
        if not isinstance(self.updated_at, str) or not self.updated_at:
            raise _invalid()


@dataclass(frozen=True)
class ChangeProposal:
    proposal_id: str
    owner_id: str
    kind: str
    reason: str
    status: ProposalStatus
    subject_revision: int
    risk_level: RiskLevel
    resources: tuple[RiskResource, ...]
    resource_digests: tuple[ResourceDigest, ...]
    targets: tuple[ProposalTarget, ...]
    created_at: str
    updated_at: str
    active_journal_id: str | None = None

    def __post_init__(self) -> None:
        require_opaque_id(self.proposal_id)
        require_opaque_id(self.owner_id)
        require_opaque_id(self.kind)
        if not isinstance(self.reason, str) or not self.reason or "\x00" in self.reason:
            raise _invalid()
        if not isinstance(self.status, ProposalStatus):
            raise _invalid()
        if not is_strict_int(self.subject_revision) or self.subject_revision < 0:
            raise _invalid()
        if not isinstance(self.risk_level, RiskLevel):
            raise _invalid()
        if not self.resources or not self.resource_digests or not self.targets:
            raise _invalid()
        if not isinstance(self.created_at, str) or not self.created_at:
            raise _invalid()
        if not isinstance(self.updated_at, str) or not self.updated_at:
            raise _invalid()

    def to_target_files(self) -> tuple[TargetFile, ...]:
        return tuple(target.to_target_file() for target in self.targets)


@dataclass(frozen=True)
class FileJournalEntry:
    normalized_rel_path: str
    target_root: str
    managed_format: ManagedFormat
    slice_id: str
    original: FileOriginalState
    phase: FileJournalPhase
    original_digest: str | None
    original_physical_id: str | None
    replacement_digest: str | None
    replacement_staging_path: str
    backup_path: str | None
    replacement_physical_id: str | None = None
    parent_physical_id: str | None = None


@dataclass(frozen=True)
class ApplyJournal:
    journal_id: str
    proposal_id: str
    direction: JournalDirection
    status: ProposalStatus
    grant_id: str
    staging_dir: str
    files: tuple[FileJournalEntry, ...]
    created_at: str
    updated_at: str
