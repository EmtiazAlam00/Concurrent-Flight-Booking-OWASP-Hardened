"""Seat holds: the contended write.

Acquiring a hold is a *single conditional UPDATE*, not read-then-write:

    UPDATE seat_inventory SET status='held', ...
     WHERE flight_id = :f AND seat_no = :s
       AND (status = 'available' OR (status='held' AND hold_expires_at < now()))
    RETURNING ...

The UPDATE takes the row lock itself. Two concurrent requests serialize on that
lock; the loser then re-evaluates the WHERE against the winner's committed row,
matches nothing, and gets zero rows back. Zero rows *is* the answer — no race
window, no retry loop, one round trip.

The `hold_expires_at < now()` clause is the other half of the design: an expired
hold is already not a hold. Availability never depends on the sweep job having
run. See docs/ADR-0001.
"""

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import Request
from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db import rows_affected
from app.domain.enums import SeatStatus
from app.domain.models import Flight, SeatInventory, Ticket
from app.errors import NotFound, SeatUnavailable, TooManyHolds


def takeable(seat_alias=SeatInventory):
    """The one definition of 'this seat can be taken right now'.

    Every query that asks the question uses this, so availability, holding and
    booking can never disagree about what 'free' means.
    """
    return or_(
        seat_alias.status == SeatStatus.AVAILABLE,
        and_(
            seat_alias.status == SeatStatus.HELD,
            seat_alias.hold_expires_at < func.now(),
        ),
    )


def hold_is_live(seat: SeatInventory) -> bool:
    return (
        seat.status == SeatStatus.HELD
        and seat.hold_expires_at is not None
        and seat.hold_expires_at > datetime.now(UTC)
    )


async def count_active_holds(session: AsyncSession, user_id: uuid.UUID) -> int:
    return int(
        await session.scalar(
            select(func.count())
            .select_from(SeatInventory)
            .where(
                SeatInventory.held_by_user_id == user_id,
                SeatInventory.status == SeatStatus.HELD,
                SeatInventory.hold_expires_at > func.now(),
            )
        )
        or 0
    )


async def acquire_hold(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    flight_id: uuid.UUID,
    seat_no: str,
    ttl_seconds: int | None = None,
    request: Request | None = None,
) -> SeatInventory:
    ttl = ttl_seconds or settings.hold_ttl_seconds

    # Squatting on inventory is itself an abuse vector (denial of inventory),
    # so cap concurrent holds per account.
    active = await count_active_holds(session, user_id)
    if active >= settings.max_active_holds_per_user:
        raise TooManyHolds(
            f"You already hold {active} seats; release one or wait for a hold to expire."
        )

    hold_id = uuid.uuid4()
    stmt = (
        update(SeatInventory)
        .where(
            SeatInventory.flight_id == flight_id,
            SeatInventory.seat_no == seat_no.upper(),
            takeable(),
        )
        .values(
            status=SeatStatus.HELD,
            held_by_user_id=user_id,
            hold_id=hold_id,
            hold_expires_at=func.now() + timedelta(seconds=ttl),
            booking_id=None,
            version=SeatInventory.version + 1,
        )
        .returning(SeatInventory)
        .execution_options(synchronize_session=False)
    )
    seat = (await session.execute(stmt)).scalar_one_or_none()

    if seat is None:
        # Zero rows means either the seat doesn't exist or somebody else has it.
        # Distinguish the two so the caller gets an honest status code.
        exists = await session.scalar(
            select(func.count())
            .select_from(SeatInventory)
            .where(
                SeatInventory.flight_id == flight_id,
                SeatInventory.seat_no == seat_no.upper(),
            )
        )
        if not exists:
            raise NotFound(f"Flight has no seat {seat_no.upper()}")
        raise SeatUnavailable(f"Seat {seat_no.upper()} is already taken")

    await session.commit()
    await session.refresh(seat)
    return seat


async def release_hold(
    session: AsyncSession, *, hold_id: uuid.UUID, user_id: uuid.UUID | None = None
) -> bool:
    """Release a hold. Conditional on the hold still being the one we think it is."""
    conditions = [
        SeatInventory.hold_id == hold_id,
        SeatInventory.status == SeatStatus.HELD,
    ]
    if user_id is not None:
        conditions.append(SeatInventory.held_by_user_id == user_id)

    result = await session.execute(
        update(SeatInventory)
        .where(*conditions)
        .values(
            status=SeatStatus.AVAILABLE,
            held_by_user_id=None,
            hold_id=None,
            hold_expires_at=None,
            version=SeatInventory.version + 1,
        )
        .execution_options(synchronize_session=False)
    )
    await session.commit()
    return rows_affected(result) > 0


async def release_seats_for_booking(session: AsyncSession, *, booking_id: uuid.UUID) -> int:
    """Hand a booking's seats back to inventory, voiding any tickets they back.

    Used by both compensation and cancellation.

    The ticket voiding lives here rather than at the call sites deliberately: a
    seat returning to inventory while a live ticket still points at it is
    exactly the state that makes the seat unsellable forever, because the next
    booking collides with the old ticket's unique index. Releasing and voiding
    are one operation, so keep them in one function.

    Does not commit — the caller owns the transaction, so the release, the
    voiding and the audit row all land together or not at all.
    """
    await session.execute(
        update(Ticket)
        .where(Ticket.booking_id == booking_id, Ticket.voided_at.is_(None))
        .values(voided_at=func.now())
        .execution_options(synchronize_session=False)
    )
    result = await session.execute(
        update(SeatInventory)
        .where(SeatInventory.booking_id == booking_id)
        .values(
            status=SeatStatus.AVAILABLE,
            held_by_user_id=None,
            hold_id=None,
            hold_expires_at=None,
            booking_id=None,
            version=SeatInventory.version + 1,
        )
        .execution_options(synchronize_session=False)
    )
    return rows_affected(result)


async def get_flight_or_404(session: AsyncSession, flight_id: uuid.UUID) -> Flight:
    flight = await session.get(Flight, flight_id)
    if flight is None:
        raise NotFound("No such flight")
    return flight
