"""Policy ports: what storage may ask the policy store (spec 5.3, 5.7).

Storage never imports the policy store itself; it reads policy through these protocols.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from superbrain.core.jsonvalue import JsonValue


class IntentKind(StrEnum):
    TOMBSTONE = "tombstone"
    QUARANTINE = "quarantine"
    CREDENTIAL_REVOKE = "credential_revoke"
    WORKSPACE_REGISTER = "workspace_register"
    SIGNER_RESET = "signer_reset"
    REPO_POLICY_SET = "repo_policy_set"
    LAYER2_STATE_SET = "layer2_state_set"
    RECOVERY_GRANT_OPENED = "recovery_grant_opened"
    RECOVERY_GRANT_ENDED = "recovery_grant_ended"


@dataclass(frozen=True)
class Intent:
    intent_id: str
    kind: IntentKind
    payload: Mapping[str, JsonValue]
    created_at: str


class PolicyView(Protocol):
    def is_quarantined(self, digest: str) -> bool: ...

    def is_tombstoned(self, holder_kind: str, holder_id: str) -> bool: ...


class PolicySource(PolicyView, Protocol):
    @property
    def store_id(self) -> str:
        """The id of the main store this policy store belongs to."""
        ...

    def intents(self) -> Sequence[Intent]:
        """Every recorded intent; the main store decides which it has already applied."""
        ...
