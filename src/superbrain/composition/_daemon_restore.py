"""Online ``/v2/operator/restore`` composition handler and daemon session rebind."""

from __future__ import annotations

import contextlib
import threading
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Literal

from superbrain.application.approvals import OperatorHandle, RestoreHandler
from superbrain.application.continuity_worker import sweep_legacy_continuity_copies
from superbrain.application.jobs import JobService
from superbrain.application.journal_recovery import reconcile_and_classify_journals
from superbrain.application.maintenance import (
    RestoreOutcome,
    outcome_to_json,
    preview_online_restore,
    validate_restore_approval_target,
)
from superbrain.application.review_apply import ReviewApplyService
from superbrain.composition._daemon_session import _AdmittedOwnerSession, _DaemonCompositeDomain
from superbrain.composition._endpoint import publish_endpoint
from superbrain.composition._maintenance_wiring import ensure_maintenance_backend
from superbrain.composition.kernel_projections import kernel_store_extensions
from superbrain.core._kernel_approval import ApprovalChannel, ApprovalMessage, canonical_utc
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    ENDPOINT_HOST,
    ENDPOINT_VERSION,
    Endpoint,
    Ready,
    RequestAuthView,
    ShallowHealthMeta,
)
from superbrain.core.proposals import ManagedFormat
from superbrain.ports.clock import Clock
from superbrain.ports.os import OsAdapters
from superbrain.ports.proposals import ConfigMergerPort, MergeOutput
from superbrain.storage.capture_events import KernelCaptureStore
from superbrain.storage.idempotency import StagedKernelStore
from superbrain.storage.jobs import has_legacy_incomplete_settled_projections
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.proposals import PolicyApplyAuthority, StoreProposalAdapter
from superbrain.storage.restore import (
    drain_published_restore_effects,
    read_restore_epoch,
    restore_policy,
    restore_store,
)
from superbrain.storage.runtime import Runtime
from superbrain.storage.sessions import SessionStore
from superbrain.storage.store import Store
from superbrain.workers.executor import JobExecutor


class LazyConfigMerger(ConfigMergerPort):
    """Defer importing harness-config parsers (tomlkit/json) until config slice merge/remove is needed."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._inner: ConfigMergerPort | None = None

    def _get(self) -> ConfigMergerPort:
        if self._inner is None:
            with self._lock:
                if self._inner is None:
                    from superbrain.adapters.harness_config.merger import SharedConfigMergerAdapter

                    self._inner = SharedConfigMergerAdapter()
        return self._inner

    def apply_slice(
        self,
        existing_text: str | None,
        *,
        managed_format: ManagedFormat,
        slice_id: str,
        replacement_bytes: bytes,
        expected_slice_digest: str | None,
    ) -> MergeOutput:
        return self._get().apply_slice(
            existing_text,
            managed_format=managed_format,
            slice_id=slice_id,
            replacement_bytes=replacement_bytes,
            expected_slice_digest=expected_slice_digest,
        )

    def remove_slice(
        self,
        existing_text: str,
        *,
        managed_format: ManagedFormat,
        slice_id: str,
        expected_slice_digest: str | None,
    ) -> MergeOutput:
        return self._get().remove_slice(
            existing_text,
            managed_format=managed_format,
            slice_id=slice_id,
            expected_slice_digest=expected_slice_digest,
        )


def build_review_apply_service(
    store: Store,
    policy: PolicyStore,
    root_dir: Path,
    adapters: OsAdapters,
    *,
    service_cls: type[ReviewApplyService] = ReviewApplyService,
) -> ReviewApplyService | None:
    """Construct ``ReviewApplyService`` when both stores support v5/v4 proposal tracking."""
    if store.schema_version >= 5 and policy.schema_version >= 4:
        return service_cls(
            StoreProposalAdapter(store, adapters),
            PolicyApplyAuthority(policy),
            adapters,
            data_root=root_dir,
            home_dir=Path.home(),
            config_merger=LazyConfigMerger(),
        )
    return None


class DaemonRestoreHandler(RestoreHandler):
    """Owner-thread handler backing online ``/v2/operator/restore`` with immediate authority rebind."""

    def __init__(
        self,
        *,
        session: _AdmittedOwnerSession,
        adapters: OsAdapters,
        clock: Clock,
        executor: JobExecutor | None,
        composite_domain: _DaemonCompositeDomain,
        instance_id: str,
        operator: OperatorHandle,
        review_apply_cls: type[ReviewApplyService] = ReviewApplyService,
    ) -> None:
        self._session = session
        self._adapters = adapters
        self._clock = clock
        self._executor = executor
        self._composite_domain = composite_domain
        self._instance_id = instance_id
        self._operator = operator
        self._review_apply_cls = review_apply_cls

    def preview(self, target: Literal["store", "policy"], backup: Path) -> dict[str, JsonValue]:
        rt = self._session.rt
        return preview_online_restore(
            rt.root,
            rt.lease,
            rt.policy,
            self._adapters,
            target=target,
            backup=backup,
            now=self._clock.now(),
            store_migrations=KERNEL_STORE_MIGRATIONS,
            policy_migrations=KERNEL_POLICY_MIGRATIONS,
            backend=ensure_maintenance_backend(),
        )

    def validate_execute(
        self,
        target: Literal["store", "policy"],
        backup: Path,
        message: ApprovalMessage,
    ) -> None:
        rt = self._session.rt
        validate_restore_approval_target(
            rt.root,
            rt.lease,
            self._adapters,
            target=target,
            backup=backup,
            store_id=rt.store.store_id,
            message=message,
            now=self._clock.now(),
            store_migrations=KERNEL_STORE_MIGRATIONS,
            policy_migrations=KERNEL_POLICY_MIGRATIONS,
            backend=ensure_maintenance_backend(),
        )

    def execute(
        self,
        target: Literal["store", "policy"],
        backup: Path,
        message: ApprovalMessage,
        *,
        signer_id: str | None,
        channel: ApprovalChannel,
        new_sign_count: int | None,
    ) -> dict[str, JsonValue]:
        rt = self._session.rt
        _, _, now_dt = validate_restore_approval_target(
            rt.root,
            rt.lease,
            self._adapters,
            target=target,
            backup=backup,
            store_id=rt.store.store_id,
            message=message,
            now=self._clock.now(),
            store_migrations=KERNEL_STORE_MIGRATIONS,
            policy_migrations=KERNEL_POLICY_MIGRATIONS,
            backend=ensure_maintenance_backend(),
        )
        rt.policy.consume_approval(message, signer_id=signer_id, channel=channel, new_sign_count=new_sign_count)
        if target == "store":
            return self._execute_store_restore(rt, backup, now_dt)
        return self._execute_policy_restore(rt, backup, now_dt)

    def _open_store(self, rt: Runtime, policy: PolicyStore) -> Store:
        proj_handlers, proj_kinds = kernel_store_extensions()
        return Store.open(
            rt.root,
            rt.lease,
            self._adapters,
            policy,
            proj_handlers,
            proj_kinds,
            migrations=KERNEL_STORE_MIGRATIONS,
        )

    def _post_restore_reconcile(self, new_rt: Runtime) -> JobService:
        if has_legacy_incomplete_settled_projections(new_rt.store, new_rt.lease):
            new_rt.store.rebuild_projections()
            if has_legacy_incomplete_settled_projections(new_rt.store, new_rt.lease):
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        job_service = self._rebind_live(new_rt)
        if new_rt.store.schema_version >= 7 and new_rt.policy.schema_version >= 5:
            sweep_legacy_continuity_copies(job_service, SessionStore(new_rt.store, new_rt.policy))
        job_service.recover(new_rt.lease.epoch)
        if new_rt.store.schema_version >= 5 and new_rt.policy.schema_version >= 4:
            reconcile_and_classify_journals(
                StoreProposalAdapter(new_rt.store, self._adapters),
                PolicyApplyAuthority(new_rt.policy),
                self._adapters,
                data_root=new_rt.root.root,
                home_dir=Path.home(),
                config_merger=LazyConfigMerger(),
                now_utc_fn=lambda: canonical_utc(self._clock.now()),
            )
        return job_service

    def _execute_store_restore(self, rt: Runtime, backup: Path, now_dt: datetime) -> dict[str, JsonValue]:
        policy = rt.policy
        store_id = policy.store_id
        rt.store.close()
        try:
            rep = restore_store(
                rt.root,
                rt.lease,
                self._adapters,
                backup,
                policy,
                now_dt,
                migrations=KERNEL_STORE_MIGRATIONS,
            )
        except BaseException:
            with contextlib.suppress(BrainError):
                reopened = self._open_store(rt, policy)
                self._rebind_live(replace(rt, store=reopened))
            raise
        new_store = self._open_store(rt, policy)
        new_rt = replace(rt, store=new_store)
        self._post_restore_reconcile(new_rt)
        re_epoch = read_restore_epoch(new_rt.root, schema_version=new_store.schema_version, os_=self._adapters)
        return outcome_to_json(
            RestoreOutcome(
                target_kind="store",
                store_id=store_id,
                restored_from=backup,
                replaced_dir=rep.replaced_dir,
                new_epoch=rep.new_epoch,
                restore_epoch=re_epoch,
                trust_generation=policy.trust_generation(),
            )
        )

    def _execute_policy_restore(self, rt: Runtime, backup: Path, now_dt: datetime) -> dict[str, JsonValue]:
        store_id = rt.store.store_id
        store_schema_ver = rt.store.schema_version
        rt.store.close()
        rt.policy.close()
        try:
            rep = restore_policy(
                rt.root,
                rt.lease,
                self._adapters,
                backup,
                store_id=store_id,
                now=now_dt,
                migrations=KERNEL_POLICY_MIGRATIONS,
            )
        except BaseException:
            with contextlib.suppress(BrainError):
                reopened_pol = PolicyStore.open(
                    rt.root, rt.lease, self._adapters, migrations=KERNEL_POLICY_MIGRATIONS
                )
                reopened_store = self._open_store(rt, reopened_pol)
                self._rebind_live(replace(rt, store=reopened_store, policy=reopened_pol))
            raise
        new_policy = PolicyStore.open(rt.root, rt.lease, self._adapters, migrations=KERNEL_POLICY_MIGRATIONS)
        drain_published_restore_effects(
            rt.root,
            rt.lease,
            self._adapters,
            new_policy,
            now=self._clock.now(),
            target_schema=store_schema_ver,
        )
        new_store = self._open_store(rt, new_policy)
        new_rt = replace(rt, store=new_store, policy=new_policy)
        self._post_restore_reconcile(new_rt)
        re_epoch = (
            read_restore_epoch(new_rt.root, schema_version=new_store.schema_version, os_=self._adapters)
            if new_store.schema_version >= 5
            else 0
        )
        return outcome_to_json(
            RestoreOutcome(
                target_kind="policy",
                store_id=store_id,
                restored_from=backup,
                replaced_dir=rep.replaced_dir,
                new_epoch=rep.new_epoch,
                restore_epoch=re_epoch,
                trust_generation=new_policy.trust_generation(),
            )
        )

    def _rebind_live(self, rt: Runtime) -> JobService:
        new_epoch = rt.lease.epoch
        epoch_bumped = new_epoch != self._session.auth_gate.identity.writer_epoch
        job_store = StagedKernelStore(rt.store, rt.policy, writer_epoch=new_epoch)
        job_service = JobService(
            job_store,
            job_store,
            rt.policy,
            self._clock,
            writer_epoch=new_epoch,
            accounting=rt.policy if rt.policy.schema_version >= 4 else None,
            cancel_signal=self._executor.cancel if self._executor is not None else None,
        )
        self._composite_domain.rebind_job_service(job_service)
        from superbrain.composition._daemon_session import make_default_handoff_domain_factory

        self._composite_domain.rebind_fallback_factory(
            make_default_handoff_domain_factory(rt=rt, clock=self._clock, writer_epoch=new_epoch)
        )
        new_ready: Ready | None = None
        if epoch_bumped:
            new_endpoint = Endpoint(
                version=ENDPOINT_VERSION,
                host=ENDPOINT_HOST,
                port=self._session.listener.port,
                store_id=rt.store.store_id,
                writer_epoch=new_epoch,
                instance_id=self._instance_id,
            )
            publish_endpoint(rt.root, rt.lease, new_endpoint, self._adapters)
            new_ready = replace(self._session.ready, endpoint=new_endpoint, identity=new_endpoint.identity)
        self._session.rebind_after_restore(rt=rt, job_store=job_store, job_service=job_service, ready=new_ready)
        snap = self._session.auth_gate.merge_runtime_capabilities(rt.policy.snapshot())
        has_active_cred = any(
            not cred.revoked and snap.principals.get(cred.principal.principal_id) == cred.principal
            for cred in snap.credentials.values()
        )
        if has_active_cred:
            key_id, key_bytes = rt.policy.request_digest_key()
            health_meta = ShallowHealthMeta(
                store_id=rt.store.store_id,
                writer_epoch=new_epoch,
                instance_id=self._instance_id,
                schema_version=rt.store.schema_version,
                policy_schema_version=rt.policy.schema_version,
                tls_not_after=self._session.ready.tls_not_after,
                idempotency_clock_untrusted=self._session.bridge_clock_untrusted(),
                capture_gaps_present=KernelCaptureStore(rt.store).has_gaps() if rt.store.schema_version >= 6 else False,
            )
            view = RequestAuthView(
                version=self._session.auth_gate.next_version(),
                auth=snap,
                active_request_key_id=key_id,
                active_request_key_bytes=key_bytes,
            )
            if epoch_bumped:
                self._session.auth_gate.rebind_writer_epoch(new_epoch, view, health_meta=health_meta)
            else:
                self._session.auth_gate.publish_view(view, health_meta=health_meta)
        else:
            self._session.auth_gate.invalidate()
        svc = self._operator.service()
        if svc is not None:
            svc.rebind_authorities(
                rt.policy,
                build_review_apply_service(
                    rt.store,
                    rt.policy,
                    rt.root.root,
                    self._adapters,
                    service_cls=self._review_apply_cls,
                ),
            )
        return job_service
