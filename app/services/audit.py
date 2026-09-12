"""The append-only booking audit trail.

Audit rows are written **in the same transaction as the state change they
describe**. That is the whole point: if the transaction rolls back, so does its
audit row, and the log can never claim something happened that didn't. (Security
events are the opposite — see app/security/events.py — because a denial must
survive the rollback of the thing it denied.)

`seq` is a gap-free per-booking counter. A gap means a lost write, which is why
tests assert on it.
"""

import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.enums import AuditEventType, BookingState
from app.domain.models import BookingAudit


async def record(
    session: AsyncSession,
    booking_id: uuid.UUID,
    event_type: AuditEventType,
    *,
    actor_type: str = "system",
    actor_id: uuid.UUID | None = None,
    from_state: BookingState | str | None = None,
    to_state: BookingState | str | None = None,
    detail: dict[str, Any] | None = None,
) -> BookingAudit:
    next_seq = await session.scalar(
        select(func.coalesce(func.max(BookingAudit.seq), 0) + 1).where(
            BookingAudit.booking_id == booking_id
        )
    )
    row = BookingAudit(
        booking_id=booking_id,
        seq=int(next_seq or 1),
        event_type=event_type,
        actor_type=actor_type,
        actor_id=actor_id,
        from_state=str(from_state) if from_state else None,
        to_state=str(to_state) if to_state else None,
        detail=detail or {},
    )
    session.add(row)
    # Flush so a second record() in the same transaction sees this seq.
    await session.flush()
    return row
