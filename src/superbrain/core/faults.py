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
    # Task 8: kernel daemon startup and two-target offline migration
    "daemon.after_bind_before_endpoint",
    "daemon.after_endpoint_publish",
    "kernel.migrate.after_policy_swap",
    "kernel.before_commit",
    "kernel.after_commit_before_response",
    "jobs.after_lease",
    "jobs.after_running",
    "jobs.after_invocation_reserve",
    "jobs.after_cancel_commit",
    "jobs.after_usage_settle_commit",
    # I3-3: ApplyJournal & recovery_grant crashpoints
    "apply.after_policy_turn_intent",
    "apply.before_move_original",
    "apply.after_move_before_phase",
    "apply.before_publish_replacement",
    "apply.after_publish_before_phase",
    "rollback.after_policy_turn_intent",
    "rollback.before_first_move",
    "rollback.after_move_replacement",
    "rollback.after_restore_last_original",
    "apply.after_policy_grant_ended",
})

KNOWN_PAUSEPOINTS: frozenset[str] = KNOWN_CRASHPOINTS | {"writer.held"}


def crashpoint(name: str) -> None:
    """Every crashpoint is also a pausepoint of the same name: it pauses first, then crashes if selected.

    For testing the crash harness only: a name listed in ``SUPERBRAIN_DISABLE_CRASHPOINTS_FOR_TEST`` (comma
    separated) is skipped entirely, neither pausing nor crashing, as if its call had been removed from the code. The
    crash-matrix test uses it to show the matrix fails when a crashpoint stops firing. Unset, it changes nothing.
    """
    assert name in KNOWN_CRASHPOINTS, f"unregistered crashpoint {name!r}"
    disabled = os.environ.get("SUPERBRAIN_DISABLE_CRASHPOINTS_FOR_TEST")
    if disabled is not None and name in {part.strip() for part in disabled.split(",")}:
        return
    pausepoint(name)
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
