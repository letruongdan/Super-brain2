"""Slot-derived capture identities shared by the hook (outbox fallback) and the daemon (gap replay rule)."""

from __future__ import annotations

from superbrain.core.canonical import digest_bytes

__all__ = ["fallback_gap_id"]


def fallback_gap_id(producer_stream: str, sequence: int) -> str:
    """Gap id derived from the slot, so every fallback for one slot names the same gap (hook/daemon contract)."""
    slot = (producer_stream + "\n" + str(sequence)).encode()
    return "gap-" + digest_bytes(slot)[7:39]
