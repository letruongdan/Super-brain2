"""Canonical JSON codecs for ``ChangeProposal``, ``ApplyJournal``, and ``ManagedSliceManifest`` CAS blobs."""

from __future__ import annotations

import json
from typing import Any

from superbrain.core._kernel_approval import RiskLevel, RiskResource
from superbrain.core._kernel_base import ResourceDigest
from superbrain.core.canonical import canonical_json
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.proposals import (
    ApplyJournal,
    ChangeProposal,
    FileJournalEntry,
    FileJournalPhase,
    FileOriginalState,
    JournalDirection,
    ManagedFormat,
    ManagedSliceManifest,
    ProposalStatus,
    ProposalTarget,
)

__all__ = [
    "decode_journal",
    "decode_manifest",
    "decode_proposal",
    "encode_journal",
    "encode_manifest",
    "encode_proposal",
]


def encode_proposal(proposal: ChangeProposal) -> bytes:
    payload: dict[str, JsonValue] = {
        "proposal_id": proposal.proposal_id,
        "owner_id": proposal.owner_id,
        "kind": proposal.kind,
        "reason": proposal.reason,
        "subject_revision": proposal.subject_revision,
        "risk_level": proposal.risk_level.value,
        "resources": [
            {
                "component": r.component,
                "executable": r.executable,
                "command_reference": r.command_reference,
                "outside_guidance_block": r.outside_guidance_block,
            }
            for r in proposal.resources
        ],
        "resource_digests": [d.to_dict() for d in proposal.resource_digests],
        "targets": [
            {
                "rel_path": t.rel_path,
                "normalized_rel_path": t.normalized_rel_path,
                "managed_format": t.managed_format.value,
                "slice_id": t.slice_id,
                "base_present": t.base_present,
                "base_digest": t.base_digest,
                "base_physical_id": t.base_physical_id,
                "replacement_digest": t.replacement_digest,
                "managed_slice_digest": t.managed_slice_digest,
                "target_root": t.target_root,
                "parent_physical_id": t.parent_physical_id,
            }
            for t in proposal.targets
        ],
        "created_at": proposal.created_at,
    }
    return canonical_json(payload)


def decode_proposal(
    raw_bytes: bytes,
    *,
    status: str,
    subject_revision: int,
    active_journal_id: str | None,
    updated_at: str,
) -> ChangeProposal:
    data: dict[str, Any] = json.loads(raw_bytes)
    resources = tuple(
        RiskResource(
            component=str(r["component"]),
            executable=bool(r["executable"]),
            command_reference=bool(r["command_reference"]),
            outside_guidance_block=bool(r["outside_guidance_block"]),
        )
        for r in data["resources"]
    )
    digests = tuple(ResourceDigest.from_dict(d) for d in data["resource_digests"])
    targets = tuple(
        ProposalTarget(
            rel_path=str(t["rel_path"]),
            normalized_rel_path=str(t["normalized_rel_path"]),
            managed_format=ManagedFormat(str(t["managed_format"])),
            slice_id=str(t["slice_id"]),
            base_present=bool(t["base_present"]),
            base_digest=t["base_digest"],
            base_physical_id=t["base_physical_id"],
            replacement_digest=t["replacement_digest"],
            managed_slice_digest=t.get("managed_slice_digest"),
            target_root=str(t.get("target_root", "")),
            parent_physical_id=str(t.get("parent_physical_id", "")),
        )
        for t in data["targets"]
    )
    return ChangeProposal(
        proposal_id=str(data["proposal_id"]),
        owner_id=str(data["owner_id"]),
        kind=str(data["kind"]),
        reason=str(data["reason"]),
        status=ProposalStatus(status),
        subject_revision=subject_revision,
        risk_level=RiskLevel(str(data["risk_level"])),
        resources=resources,
        resource_digests=digests,
        targets=targets,
        created_at=str(data["created_at"]),
        updated_at=updated_at,
        active_journal_id=active_journal_id,
    )


def encode_journal(journal: ApplyJournal) -> bytes:
    payload: dict[str, JsonValue] = {
        "journal_id": journal.journal_id,
        "proposal_id": journal.proposal_id,
        "direction": journal.direction.value,
        "status": journal.status.value,
        "grant_id": journal.grant_id,
        "staging_dir": journal.staging_dir,
        "files": [
            {
                "normalized_rel_path": f.normalized_rel_path,
                "target_root": f.target_root,
                "managed_format": f.managed_format.value,
                "slice_id": f.slice_id,
                "original": f.original.value,
                "phase": f.phase.value,
                "original_digest": f.original_digest,
                "original_physical_id": f.original_physical_id,
                "replacement_digest": f.replacement_digest,
                "replacement_staging_path": f.replacement_staging_path,
                "backup_path": f.backup_path,
                "replacement_physical_id": f.replacement_physical_id,
                "parent_physical_id": f.parent_physical_id,
            }
            for f in journal.files
        ],
        "created_at": journal.created_at,
        "updated_at": journal.updated_at,
    }
    return canonical_json(payload)


def decode_journal(raw_bytes: bytes) -> ApplyJournal:
    data: dict[str, Any] = json.loads(raw_bytes)
    files = tuple(
        FileJournalEntry(
            normalized_rel_path=str(f["normalized_rel_path"]),
            target_root=str(f["target_root"]),
            managed_format=ManagedFormat(str(f["managed_format"])),
            slice_id=str(f["slice_id"]),
            original=FileOriginalState(str(f["original"])),
            phase=FileJournalPhase(str(f["phase"])),
            original_digest=f["original_digest"],
            original_physical_id=f["original_physical_id"],
            replacement_digest=f["replacement_digest"],
            replacement_staging_path=str(f["replacement_staging_path"]),
            backup_path=f["backup_path"],
            replacement_physical_id=f.get("replacement_physical_id"),
            parent_physical_id=f.get("parent_physical_id"),
        )
        for f in data["files"]
    )
    return ApplyJournal(
        journal_id=str(data["journal_id"]),
        proposal_id=str(data["proposal_id"]),
        direction=JournalDirection(str(data["direction"])),
        status=ProposalStatus(str(data["status"])),
        grant_id=str(data["grant_id"]),
        staging_dir=str(data["staging_dir"]),
        files=files,
        created_at=str(data["created_at"]),
        updated_at=str(data["updated_at"]),
    )


def encode_manifest(manifest: ManagedSliceManifest) -> bytes:
    payload: dict[str, JsonValue] = {
        "proposal_id": manifest.proposal_id,
        "target_root": manifest.target_root,
        "normalized_rel_path": manifest.normalized_rel_path,
        "managed_format": manifest.managed_format.value,
        "slice_id": manifest.slice_id,
        "slice_digest": manifest.slice_digest,
        "full_file_digest": manifest.full_file_digest,
        "updated_at": manifest.updated_at,
    }
    return canonical_json(payload)


def decode_manifest(raw_bytes: bytes) -> ManagedSliceManifest:
    data: dict[str, Any] = json.loads(raw_bytes)
    return ManagedSliceManifest(
        proposal_id=str(data["proposal_id"]),
        normalized_rel_path=str(data["normalized_rel_path"]),
        managed_format=ManagedFormat(str(data["managed_format"])),
        slice_id=str(data["slice_id"]),
        slice_digest=str(data["slice_digest"]),
        full_file_digest=str(data["full_file_digest"]),
        updated_at=str(data["updated_at"]),
        target_root=str(data.get("target_root", "")),
    )
