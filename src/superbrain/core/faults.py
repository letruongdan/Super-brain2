"""Fault injection hooks for crash tests, driven by environment variables."""

import os
import sys

KNOWN_CRASHPOINTS: frozenset[str] = frozenset({
    "writer.mid_slot_write",
    "ledger.before_commit",
    "ledger.after_commit",
    "cas.after_staging_write",
    "cas.after_rename",
    "policy.after_intent_commit",
    "intents.after_store_apply",
    "backup.after_db_snapshot",
    "backup.after_blob_copy",
    "restoring.store.after_stage",
    "restoring.store.between_renames",
    "restoring.policy.after_generation_persist",
    "restoring.policy.after_stage",
    "restoring.policy.between_renames",
    "restoring.policy.before_hwm_update",
    "migrating.store.after_stage",
    "migrating.store.between_renames",
    "migrating.policy.after_stage",
    "migrating.policy.between_renames",
})

KNOWN_PAUSEPOINTS: frozenset[str] = KNOWN_CRASHPOINTS | {"writer.held"}


def crashpoint(name: str) -> None:
    assert name in KNOWN_CRASHPOINTS, f"unregistered crashpoint {name!r}"
    if os.environ.get("SUPERBRAIN_CRASHPOINT") == name:
        sys.stderr.write(f"CRASHPOINT_HIT {name}\n")
        sys.stderr.flush()
        os._exit(86)


def pausepoint(name: str) -> None:
    assert name in KNOWN_PAUSEPOINTS, f"unregistered pausepoint {name!r}"
    if os.environ.get("SUPERBRAIN_PAUSEPOINT") == name:
        sys.stderr.write(f"PAUSED {name}\n")
        sys.stderr.flush()
        sys.stdin.readline()
