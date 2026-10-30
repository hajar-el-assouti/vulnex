"""The Celery task that runs a scan.

Each task invocation opens its own short-lived async SQLAlchemy engine
and session (app/db/session.py::worker_scoped_session) inside
`asyncio.run(...)`. This avoids adding a second, synchronous database
driver just for Celery.

Every status change goes through
services.scans.transition_scan_status(), never a plain assignment, so
a slow worker can't overwrite a state that a cancellation already
finalized.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.celery_app import get_celery_app
from app.core.config import get_settings
from app.db.session import worker_scoped_session, worker_scoped_session_factory
from app.engines.contracts import CancellationContext, ScanConfiguration, ScanContext
from app.models.scan import Scan, ScanStatus
from app.models.scan_event import ScanEventType
from app.models.scan_module_run import ScanModuleRun, ScanModuleRunStatus
from app.services import findings as findings_service
from app.services import recon_history, scans as scans_service
from app.tasks.active_web_testing_module import ActiveWebTestingModule
from app.tasks.advanced_recon_module import AdvancedReconModule
from app.tasks.cancellation import LiveCancellation, PollSessionFactory
from app.tasks.diagnostic import DiagnosticModule
from app.tasks.discovery_fuzzing_module import DiscoveryFuzzingModule
from app.tasks.recon_module import ReconModule
from app.tasks.web_vuln_module import WebVulnAssessmentModule

logger = logging.getLogger("app.tasks.scan_tasks")

celery_app = get_celery_app()

# Modules this worker can run, keyed by scan_modules.slug. Adding a
# module means adding an entry here and a ScanModule row with the same
# slug (through a migration); the orchestration loop doesn't change.
#
# active_web_testing and discovery_fuzzing are seeded with
# is_enabled=False and require active testing confirmation (see
# app/core/config.py), so they can't be selected until an operator
# enables them.
_RUNNABLE_MODULES = {
    DiagnosticModule.slug: DiagnosticModule(),
    ReconModule.slug: ReconModule(),
    AdvancedReconModule.slug: AdvancedReconModule(),
    WebVulnAssessmentModule.slug: WebVulnAssessmentModule(),
    ActiveWebTestingModule.slug: ActiveWebTestingModule(),
    DiscoveryFuzzingModule.slug: DiscoveryFuzzingModule(),
}


async def _load_scan(db, scan_id: uuid.UUID) -> Scan | None:
    result = await db.execute(
        select(Scan)
        .where(Scan.id == scan_id)
        .options(
            selectinload(Scan.module_runs).selectinload(ScanModuleRun.module),
            # Every module gets the real target row (base_url, is_authorized),
            # loaded once here with the scan.
            selectinload(Scan.target),
        )
    )
    return result.scalar_one_or_none()


async def _build_module_options(db, scan: Scan, module_run: ScanModuleRun) -> dict:
    """Extra ScanConfiguration.options for one module run, beyond the
    standard ScanContext fields every module gets. Empty for every
    module slug except "recon" -- see app/tasks/recon_module.py for
    what it does with these -- so this is a strict addition for
    diagnostic (which already ignores `options` entirely) and every
    other non-recon module."""
    if module_run.module.slug == "advanced_recon":
        # The port scan uses its own allowlist, not lab_hosts /
        # ssrf_lab_allowlist (see app/security/network_scan.py).
        # "lab_hosts" is still passed because AdvancedReconModule
        # validates the target's base_url like ReconModule does.
        #
        # Same fingerprint history as the "recon" branch, with
        # module_slug="advanced_recon", so each module has its own
        # history: a recon run is never compared with an advanced_recon
        # run.
        advanced_history_entry = await recon_history.fetch_previous_recon_run(
            db,
            target_id=scan.target_id,
            user_id=scan.initiated_by_id,
            before_run_id=module_run.id,
            module_slug="advanced_recon",
        )
        advanced_history_provider = recon_history.FrozenFingerprintHistoryProvider(
            advanced_history_entry,
            target_id=scan.target_id,
            user_id=scan.initiated_by_id,
            before_run_id=module_run.id,
        )
        return {
            "target_is_authorized": scan.target.is_authorized,
            "lab_hosts": list(get_settings().ssrf_lab_allowlist),
            "allowed_ports": list(get_settings().advanced_recon_default_allowed_ports),
            "network_lab_hosts": list(get_settings().advanced_recon_network_lab_allowlist),
            "history_provider": advanced_history_provider,
            "target_id": str(scan.target_id),
            "user_id": str(scan.initiated_by_id),
        }

    if module_run.module.slug == "web_vuln_assessment":
        # Only needs the same HTTP authorization / SSRF lab inputs as
        # "recon": no fingerprint history and no port scan authorization
        # (it never opens a raw socket).
        return {
            "target_is_authorized": scan.target.is_authorized,
            "lab_hosts": list(get_settings().ssrf_lab_allowlist),
        }

    if module_run.module.slug == "active_web_testing":
        # Uses active_web_testing_lab_allowlist, not ssrf_lab_allowlist.
        # "lab_hosts" comes from the same list, so the private-network
        # SSRF exception only covers the host that gate 4 approved.
        return {
            "target_is_authorized": scan.target.is_authorized,
            "lab_hosts": list(get_settings().active_web_testing_lab_allowlist),
        }

    if module_run.module.slug == "discovery_fuzzing":
        # Uses discovery_fuzzing_lab_allowlist, not the SSRF or active
        # testing lists. "lab_hosts" comes from the same list, so the
        # private-network SSRF exception only covers the host gate 4
        # approved. "mode" is always "quick" for now.
        return {
            "target_is_authorized": scan.target.is_authorized,
            "lab_hosts": list(get_settings().discovery_fuzzing_lab_allowlist),
            "mode": "quick",
        }

    if module_run.module.slug != "recon":
        return {}

    history_entry = await recon_history.fetch_previous_recon_run(
        db,
        target_id=scan.target_id,
        user_id=scan.initiated_by_id,
        before_run_id=module_run.id,
    )
    history_provider = recon_history.FrozenFingerprintHistoryProvider(
        history_entry,
        target_id=scan.target_id,
        user_id=scan.initiated_by_id,
        before_run_id=module_run.id,
    )
    return {
        "target_is_authorized": scan.target.is_authorized,
        "lab_hosts": list(get_settings().ssrf_lab_allowlist),
        "history_provider": history_provider,
        "target_id": str(scan.target_id),
        "user_id": str(scan.initiated_by_id),
    }


async def _cancellation_requested(db, scan_id: uuid.UUID) -> bool:
    """Fresh read, not a cached flag -- this is what makes cancellation
    checked *between* module runs actually see a request made after the
    task started."""
    result = await db.execute(select(Scan.status).where(Scan.id == scan_id))
    status = result.scalar_one_or_none()
    return status == ScanStatus.CANCELLING


async def _finalize_cancelled(db, scan_id: uuid.UUID, remaining_runs: list[ScanModuleRun]) -> None:
    for run in remaining_runs:
        if run.status == ScanModuleRunStatus.PENDING:
            run.status = ScanModuleRunStatus.SKIPPED
    await db.flush()
    await scans_service.transition_scan_status(
        db,
        scan_id,
        to_status=ScanStatus.CANCELLED,
        from_statuses=[ScanStatus.CANCELLING],
        extra_values={"finished_at": datetime.now(timezone.utc)},
    )
    await scans_service.record_event(db, scan_id, ScanEventType.CANCELLED, message="Scan cancelled")


async def run_scan_logic(
    db,
    scan_id: uuid.UUID,
    *,
    poll_session_factory: PollSessionFactory | None = None,
) -> str:
    """Orchestration logic, using an already-open DB session.

    Separate from `run_scan_task` (the Celery entry point) so it can be
    tested with a SQLite session, without Postgres or a Celery worker.

    `poll_session_factory` is optional. Without it, cancellation is
    checked once before each module instead of live (see
    app/tasks/cancellation.py::LiveCancellation.start)."""
    scan = await _load_scan(db, scan_id)
    if scan is None:
        logger.error("run_scan_task: scan %s not found", scan_id)
        return "not_found"

    started = await scans_service.transition_scan_status(
        db,
        scan_id,
        to_status=ScanStatus.RUNNING,
        from_statuses=[ScanStatus.QUEUED],
        extra_values={"started_at": datetime.now(timezone.utc)},
    )
    if not started:
        # Someone cancelled it (QUEUED -> CANCELLED) before this
        # worker ever picked it up, or it's already in some other
        # state -- either way, this task has nothing to do.
        logger.info(
            "run_scan_task: scan %s was not in QUEUED (already %s); not starting",
            scan_id,
            scan.status,
        )
        await db.commit()
        return "skipped"

    await scans_service.record_event(db, scan_id, ScanEventType.STARTED, message="Scan started")
    await db.commit()

    any_failed = False
    for module_run in scan.module_runs:
        if await _cancellation_requested(db, scan_id):
            await _finalize_cancelled(db, scan_id, scan.module_runs)
            await db.commit()
            return "cancelled"

        module_impl = _RUNNABLE_MODULES.get(module_run.module.slug)
        if module_impl is None:
            # A module row exists (e.g. seeded ahead of a future
            # engine) but this worker has no implementation for it
            # yet. Never fabricate a result for it -- fail that
            # run explicitly instead of silently skipping or
            # pretending it succeeded.
            module_run.status = ScanModuleRunStatus.FAILED
            module_run.finished_at = datetime.now(timezone.utc)
            await scans_service.record_event(
                db,
                scan_id,
                ScanEventType.ERROR,
                message=f"No runnable implementation for module {module_run.module.slug!r}",
            )
            any_failed = True
            await db.flush()
            continue

        module_run.status = ScanModuleRunStatus.RUNNING
        module_run.started_at = datetime.now(timezone.utc)
        await db.flush()
        await scans_service.record_event(
            db,
            scan_id,
            ScanEventType.MODULE_STARTED,
            message=f"Module {module_run.module.slug} started",
        )
        await db.commit()

        module_options = await _build_module_options(db, scan, module_run)

        # Live cancellation check. `live_cancellation.is_cancelled` reads
        # an in-memory flag updated by a background poll on its own
        # session (not `db`, which this coroutine still uses).
        # `module_impl.run(context)` runs in a thread executor so that
        # poll can actually run at the same time; a blocking call on the
        # event loop would starve it.
        live_cancellation = LiveCancellation(
            initial_cancelled=await _cancellation_requested(db, scan_id)
        )
        live_cancellation.start(
            poll_session_factory=poll_session_factory,
            scan_id=scan_id,
            check_cancelled=_cancellation_requested,
            poll_interval_seconds=get_settings().recon_cancellation_poll_interval_seconds,
        )

        context = ScanContext(
            scan_id=scan_id,
            scan_module_run_id=module_run.id,
            target_id=scan.target_id,
            # The real Target row, loaded with the scan (see
            # selectinload(Scan.target) in _load_scan). The diagnostic module
            # ignores it.
            target_base_url=scan.target.base_url,
            configuration=ScanConfiguration(module_slug=module_run.module.slug, options=module_options),
            cancellation=CancellationContext(is_cancelled=live_cancellation.is_cancelled),
        )

        try:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(None, module_impl.run, context)
        except Exception as exc:  # pragma: no cover - defensive; diagnostic module never raises
            logger.exception("Module %s raised unexpectedly", module_run.module.slug)
            module_run.status = ScanModuleRunStatus.FAILED
            module_run.finished_at = datetime.now(timezone.utc)
            await scans_service.record_event(
                db, scan_id, ScanEventType.ERROR, message=str(exc)
            )
            any_failed = True
            await db.commit()
            await live_cancellation.stop()
            continue
        else:
            await live_cancellation.stop()

        module_run.finished_at = datetime.now(timezone.utc)
        if result.status.value == "cancelled":
            module_run.status = ScanModuleRunStatus.SKIPPED
            await db.flush()
            await _finalize_cancelled(
                db, scan_id, [r for r in scan.module_runs if r.id != module_run.id]
            )
            await db.commit()
            return "cancelled"
        elif result.status.value == "completed":
            module_run.status = ScanModuleRunStatus.COMPLETED
            # Store the module's structured output, if any. None for
            # diagnostic. Recon output is already sanitized and size-capped
            # in recon_module.py (persistence.py::build_persisted_result).
            module_run.result = result.result
            # Store the module's findings. Modules without findings return
            # an empty list, and persist_module_findings returns right away.
            # Deduplication within the scan happens in the service (see
            # app/services/findings.py).
            await findings_service.persist_module_findings(
                db,
                scan_id=scan_id,
                scan_module_id=module_run.scan_module_id,
                finding_dicts=result.findings,
            )
            await scans_service.record_event(
                db,
                scan_id,
                ScanEventType.MODULE_COMPLETED,
                message=result.summary or f"Module {module_run.module.slug} completed",
            )
        else:
            module_run.status = ScanModuleRunStatus.FAILED
            any_failed = True
            await scans_service.record_event(
                db, scan_id, ScanEventType.ERROR, message=result.error or "Module failed"
            )
        await db.commit()

    final_status = ScanStatus.FAILED if any_failed else ScanStatus.COMPLETED
    await scans_service.transition_scan_status(
        db,
        scan_id,
        to_status=final_status,
        from_statuses=[ScanStatus.RUNNING],
        extra_values={"finished_at": datetime.now(timezone.utc)},
    )
    await scans_service.record_event(
        db,
        scan_id,
        ScanEventType.COMPLETED if not any_failed else ScanEventType.ERROR,
        message="Scan finished" if not any_failed else "Scan finished with failures",
    )
    await db.commit()
    return final_status.value


async def _run_scan_with_own_session(scan_id: uuid.UUID) -> str:
    """Celery entry point: opens a task-scoped session, plus a separate
    session factory for the live cancellation poller (its own small
    connection pool), then runs the logic above. Both are disposed
    when the task finishes."""
    async with worker_scoped_session() as db, worker_scoped_session_factory() as poll_session_factory:
        return await run_scan_logic(db, scan_id, poll_session_factory=poll_session_factory)


@celery_app.task(
    name="app.tasks.scan_tasks.run_scan_task",
    bind=True,
    # Controlled, bounded retries for a transient failure raised out of
    # the task body itself (e.g. the DB was briefly unreachable) -- NOT
    # for a module's own result, which is handled explicitly above and
    # never raises up to Celery's retry machinery.
    max_retries=3,
    default_retry_delay=5,
)
def run_scan_task(self, scan_id: str) -> str:
    try:
        return asyncio.run(_run_scan_with_own_session(uuid.UUID(scan_id)))
    except Exception as exc:
        logger.exception("run_scan_task failed for scan %s", scan_id)
        try:
            raise self.retry(exc=exc)
        except self.MaxRetriesExceededError:
            # Give up: mark the scan FAILED from whatever non-terminal
            # state it's in rather than leaving it stuck RUNNING/QUEUED
            # forever because the worker kept crashing.
            asyncio.run(_mark_failed_after_retries_exhausted(uuid.UUID(scan_id), str(exc)))
            raise


async def _mark_failed_after_retries_exhausted(scan_id: uuid.UUID, error: str) -> None:
    async with worker_scoped_session() as db:
        await scans_service.transition_scan_status(
            db,
            scan_id,
            to_status=ScanStatus.FAILED,
            extra_values={"finished_at": datetime.now(timezone.utc)},
        )
        await scans_service.record_event(
            db, scan_id, ScanEventType.ERROR, message=f"Worker gave up after retries: {error}"
        )
        await db.commit()
