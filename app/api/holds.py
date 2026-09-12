import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import func, select

from app.deps import CurrentUser, DbSession
from app.domain.enums import SeatStatus
from app.domain.models import Flight, SeatInventory
from app.errors import NotFound
from app.schemas.holds import HoldRequest, HoldResponse
from app.security.authz import OwnedHold
from app.security.ratelimit import rate_limit
from app.services import holds as hold_service

router = APIRouter(prefix="/holds", tags=["holds"])


def _to_response(seat: SeatInventory, currency: str) -> HoldResponse:
    remaining = 0
    active = False
    if seat.hold_expires_at is not None:
        delta = (seat.hold_expires_at - datetime.now(UTC)).total_seconds()
        remaining = max(0, int(delta))
        active = delta > 0 and seat.status == SeatStatus.HELD
    return HoldResponse(
        hold_id=seat.hold_id,
        flight_id=seat.flight_id,
        seat_no=seat.seat_no,
        cabin=seat.cabin,
        price=seat.price,
        currency=currency,
        expires_at=seat.hold_expires_at,
        seconds_remaining=remaining,
        active=active,
    )


async def _currency_for(db, flight_id: uuid.UUID) -> str:
    return str(await db.scalar(select(Flight.currency).where(Flight.id == flight_id)) or "CAD")


@router.post(
    "",
    response_model=HoldResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit("hold"))],
    responses={409: {"description": "Seat already held or booked by someone else"}},
)
async def create_hold(
    payload: HoldRequest, request: Request, user: CurrentUser, db: DbSession
) -> HoldResponse:
    """Hold a seat for the configured TTL.

    Under a race, exactly one caller gets 201 and the rest get 409 — decided by
    a single conditional UPDATE, not by a read followed by a write. See
    app/services/holds.py.
    """
    seat = await hold_service.acquire_hold(
        db,
        user_id=user.id,
        flight_id=payload.flight_id,
        seat_no=payload.seat_no,
        request=request,
    )
    return _to_response(seat, await _currency_for(db, seat.flight_id))


@router.get("", response_model=list[HoldResponse])
async def list_my_holds(user: CurrentUser, db: DbSession) -> list[HoldResponse]:
    seats = list(
        (
            await db.scalars(
                select(SeatInventory)
                .where(
                    SeatInventory.held_by_user_id == user.id,
                    SeatInventory.status == SeatStatus.HELD,
                    SeatInventory.hold_expires_at > func.now(),
                )
                .order_by(SeatInventory.hold_expires_at)
            )
        ).all()
    )
    out = []
    for seat in seats:
        out.append(_to_response(seat, await _currency_for(db, seat.flight_id)))
    return out


@router.get("/{hold_id}", response_model=HoldResponse)
async def get_hold(seat: OwnedHold, db: DbSession) -> HoldResponse:
    """Ownership is enforced by the OwnedHold dependency — this handler never
    sees an unvalidated id."""
    return _to_response(seat, await _currency_for(db, seat.flight_id))


@router.delete("/{hold_id}", status_code=status.HTTP_204_NO_CONTENT)
async def release_hold(hold_id: uuid.UUID, seat: OwnedHold, db: DbSession) -> None:
    released = await hold_service.release_hold(db, hold_id=hold_id, user_id=seat.held_by_user_id)
    if not released:
        # It was already gone — expired, swept, or consumed by a booking.
        raise NotFound("Hold is no longer active")
