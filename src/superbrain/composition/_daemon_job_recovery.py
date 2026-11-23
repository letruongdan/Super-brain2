"""Owner-side handling of a leased job attempt the owner could not finish handling (review r10).

After a lease, a failed read (``UNREADABLE``: the payload from CAS, the job row, a store or policy read) must not
leave the job ``leased`` or ``running`` in the ledger with no work behind it for the rest of the writer epoch. The
attempt is queued again through the fenced ``JobService.retry_attempt``; if that write fails too, the lease is kept
here and tried again on the next owner pass. The leased spec is kept from the claim so a completion does not need
to read the payload again.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from superbrain.application.jobs import JobService
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import JobLease, JobSpec

_LOGGER = logging.getLogger(__name__)
# Failed reads only. Other errors keep their existing contract (e.g. a missing payload blob is INTEGRITY_FAILURE and
# a closed policy POLICY_UNAVAILABLE: the job stays leased for recovery, I2).
UNREADABLE = frozenset({ErrorCode.IO_ERROR, ErrorCode.STORE_BUSY, ErrorCode.STORAGE_FULL})


def _key(lease: JobLease) -> tuple[str, str]:
    return lease.job_id, lease.lease_id


class LeasedAttempts:
    def __init__(self, job_service: Callable[[], JobService]) -> None:
        self._job_service = job_service
        self._specs: dict[tuple[str, str], JobSpec] = {}
        self._unfinished: dict[tuple[str, str], JobLease] = {}

    def remember_spec(self, lease: JobLease, spec: JobSpec) -> None:
        self._specs[_key(lease)] = spec

    def take_spec(self, lease: JobLease) -> JobSpec | None:
        return self._specs.pop(_key(lease), None)

    def retry(self, lease: JobLease) -> None:
        """Queue the attempt again (fenced by ``lease``); keep it for the next pass if that write fails."""
        key = _key(lease)
        self._specs.pop(key, None)
        try:
            self._job_service().retry_attempt(lease)
        except BrainError as err:
            if err.code is ErrorCode.REVISION_CONFLICT:
                self._unfinished.pop(key, None)  # the lease no longer holds the job (another epoch or attempt)
                return
            self._unfinished[key] = lease
            _LOGGER.warning("daemon job retry deferred (code=%s)", err.code.value)
            return
        self._unfinished.pop(key, None)

    def retry_unfinished(self) -> None:
        for lease in list(self._unfinished.values()):
            self.retry(lease)
