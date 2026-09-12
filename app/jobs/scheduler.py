import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.config import settings
from app.jobs.sweep import sweep_expired_holds

logger = logging.getLogger("skylock.scheduler")

_scheduler: AsyncIOScheduler | None = None


def start_scheduler() -> AsyncIOScheduler:
    """Start the single background job.

    `max_instances=1` and `coalesce=True` mean a slow sweep never stacks up
    behind itself. Running several API replicas would run several sweeps, which
    is harmless — the UPDATE is conditional, so a duplicate sweep is a no-op
    rather than a conflict.
    """
    global _scheduler
    if _scheduler is not None:
        return _scheduler

    scheduler = AsyncIOScheduler(timezone="UTC")
    scheduler.add_job(
        sweep_expired_holds,
        trigger="interval",
        seconds=settings.hold_sweep_interval_seconds,
        id="sweep_expired_holds",
        max_instances=1,
        coalesce=True,
        replace_existing=True,
    )
    scheduler.start()
    logger.info("hold sweep scheduled every %ss", settings.hold_sweep_interval_seconds)
    _scheduler = scheduler
    return scheduler


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
