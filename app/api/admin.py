from datetime import datetime

from fastapi import APIRouter, Query
from sqlalchemy import select

from app.deps import AdminUser, DbSession
from app.domain.models import SecurityEvent
from app.schemas.bookings import SecurityEventResponse
from app.schemas.common import CursorPage

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/security-events", response_model=CursorPage[SecurityEventResponse])
async def list_security_events(
    _: AdminUser,
    db: DbSession,
    event_type: str | None = Query(None, max_length=40),
    severity: str | None = Query(None, pattern=r"^(info|low|medium|high|critical)$"),
    since: datetime | None = Query(None),
    cursor: int | None = Query(None, ge=0, description="Return events with id < cursor"),
    limit: int = Query(50, ge=1, le=200),
) -> CursorPage[SecurityEventResponse]:
    """Query the security event log.

    Cursor pagination on the monotonic id, because this table is appended to
    while you are reading it and an OFFSET would skip or repeat rows.
    """
    stmt = select(SecurityEvent).order_by(SecurityEvent.id.desc()).limit(limit + 1)
    if event_type:
        stmt = stmt.where(SecurityEvent.event_type == event_type)
    if severity:
        stmt = stmt.where(SecurityEvent.severity == severity)
    if since:
        stmt = stmt.where(SecurityEvent.occurred_at >= since)
    if cursor:
        stmt = stmt.where(SecurityEvent.id < cursor)

    rows = list((await db.scalars(stmt)).all())
    has_more = len(rows) > limit
    rows = rows[:limit]

    return CursorPage[SecurityEventResponse](
        items=[SecurityEventResponse.model_validate(r) for r in rows],
        next_cursor=rows[-1].id if rows and has_more else None,
        has_more=has_more,
    )
