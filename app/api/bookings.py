from typing import Annotated

from fastapi import APIRouter, Depends, Header, Query, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import func, select

from app.deps import CurrentUser, DbSession
from app.domain.enums import AuditEventType, BookingState
from app.domain.models import Booking, BookingAudit, SeatInventory, Ticket
from app.domain.states import require_state
from app.errors import AppError
from app.schemas.bookings import (
    AuditEntryResponse,
    BookingCreate,
    BookingPatch,
    BookingResponse,
    PassengerResponse,
    TicketResponse,
)
from app.schemas.common import Page
from app.security.authz import OwnedBooking
from app.security.ratelimit import rate_limit
from app.services import audit, booking_saga, idempotency

router = APIRouter(prefix="/bookings", tags=["bookings"])

IdempotencyKeyHeader = Annotated[
    str,
    Header(
        alias="Idempotency-Key",
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9_.:-]+$",
        description=(
            "Required. A client-generated unique key (a UUID is ideal). Retrying "
            "with the same key returns the original response instead of booking "
            "again. Reusing a key with a different body is a 422."
        ),
    ),
]


async def _to_response(db, booking: Booking) -> BookingResponse:
    seat_by_passenger = dict(
        (
            await db.execute(
                select(SeatInventory.id, SeatInventory.seat_no).where(
                    SeatInventory.id.in_([p.seat_inventory_id for p in booking.passengers])
                )
            )
        ).all()
    )
    tickets = list(
        (
            await db.scalars(
                select(Ticket).where(
                    Ticket.booking_id == booking.id,
                    # Voided tickets stay in the table as history, but a voided
                    # e-ticket is not a boarding pass.
                    Ticket.voided_at.is_(None),
                )
            )
        ).all()
    )
    passenger_names = {p.id: f"{p.given_name} {p.family_name}" for p in booking.passengers}
    passenger_seat = {p.id: seat_by_passenger.get(p.seat_inventory_id) for p in booking.passengers}

    return BookingResponse(
        ref=booking.ref,
        state=booking.state,
        flight_id=booking.flight_id,
        flight_no=booking.flight.flight_no if booking.flight else None,
        src_iata=booking.flight.src_iata if booking.flight else None,
        dst_iata=booking.flight.dst_iata if booking.flight else None,
        depart_at=booking.flight.depart_at if booking.flight else None,
        total_amount=booking.total_amount,
        currency=booking.currency,
        passengers=[
            PassengerResponse(
                id=p.id,
                given_name=p.given_name,
                family_name=p.family_name,
                seat_no=passenger_seat.get(p.id),
                passport_last4=p.passport_last4,
            )
            for p in booking.passengers
        ],
        tickets=[
            TicketResponse(
                e_ticket_no=t.e_ticket_no,
                seat_no=passenger_seat.get(t.passenger_id),
                passenger_name=passenger_names.get(t.passenger_id, ""),
                issued_at=t.issued_at,
            )
            for t in tickets
        ],
        created_at=booking.created_at,
    )


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=BookingResponse,
    dependencies=[Depends(rate_limit("booking"))],
    responses={
        402: {"description": "Payment declined; your seat hold is still active"},
        403: {"description": "Blocked by card-testing controls"},
        409: {"description": "Hold expired, seat lost, or an identical request is in flight"},
        422: {"description": "Idempotency key reused with a different body"},
    },
)
async def create_booking(
    payload: BookingCreate,
    idempotency_key: IdempotencyKeyHeader,
    request: Request,
    user: CurrentUser,
    db: DbSession,
) -> Response:
    """Run the booking saga: hold -> charge -> issue tickets -> confirm.

    Idempotent on `Idempotency-Key`. Every outcome, including failures, is
    recorded against the key — so retrying a declined booking replays the 402
    rather than attempting a second charge.
    """
    endpoint = "POST /bookings"
    body = payload.model_dump(mode="json")

    # Bind the id to a plain value up front. `db.rollback()` in the error paths
    # below expires every ORM instance in this session — including the `user`
    # loaded by the auth dependency — and touching `user.id` afterwards would
    # trigger a lazy refresh outside SQLAlchemy's greenlet context.
    user_id = user.id

    replay = await idempotency.begin(
        db, key=idempotency_key, user_id=user_id, endpoint=endpoint, payload=body
    )
    if replay is not None:
        return JSONResponse(
            status_code=replay.status_code,
            content=replay.body,
            headers={"Idempotency-Replayed": "true"},
        )

    try:
        status_code, response_body = await booking_saga.run(
            db,
            user=user,
            payload=payload,
            idempotency_key=idempotency_key,
            request=request,
        )
    except AppError as exc:
        # A known outcome. Record it so a retry replays this exact answer
        # instead of running the saga (and the charge) a second time.
        await db.rollback()
        problem = exc.to_problem(str(request.url.path))
        await idempotency.complete(
            db,
            key=idempotency_key,
            user_id=user_id,
            status_code=exc.status_code,
            body=problem,
        )
        raise
    except Exception:
        # Unknown failure: we cannot describe the outcome, so drop the claim and
        # let the client retry cleanly rather than pinning them to a 500.
        await db.rollback()
        await idempotency.release(db, key=idempotency_key, user_id=user_id)
        raise

    await idempotency.complete(
        db,
        key=idempotency_key,
        user_id=user_id,
        status_code=status_code,
        body=response_body,
        booking_id=None,
    )
    return JSONResponse(status_code=status_code, content=response_body)


@router.get("", response_model=Page[BookingResponse])
async def list_bookings(
    user: CurrentUser,
    db: DbSession,
    page: int = Query(1, ge=1, le=1000),
    page_size: int = Query(20, ge=1, le=100),
) -> Page[BookingResponse]:
    """Only ever the caller's own bookings — the user filter is in the query."""
    total = int(
        await db.scalar(select(func.count()).select_from(Booking).where(Booking.user_id == user.id))
        or 0
    )
    rows = list(
        (
            await db.scalars(
                select(Booking)
                .where(Booking.user_id == user.id)
                .order_by(Booking.created_at.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        ).all()
    )
    return Page[BookingResponse](
        items=[await _to_response(db, b) for b in rows],
        page=page,
        page_size=page_size,
        total=total,
        has_more=page * page_size < total,
    )


@router.get("/{booking_ref}", response_model=BookingResponse)
async def get_booking(booking: OwnedBooking, db: DbSession) -> BookingResponse:
    """OWASP API #1 lives here.

    The handler takes `OwnedBooking`, never a raw `booking_ref`, so there is no
    version of this function that forgets to check ownership.
    """
    return await _to_response(db, booking)


@router.patch("/{booking_ref}", response_model=BookingResponse)
async def update_booking(
    payload: BookingPatch, booking: OwnedBooking, user: CurrentUser, db: DbSession
) -> BookingResponse:
    """Amend passenger names. Seats, price and flight are immutable."""
    require_state(booking.state, BookingState.CONFIRMED, BookingState.TICKETED)

    by_id = {p.id: p for p in booking.passengers}
    changes = []
    for update in payload.passengers:
        passenger = by_id.get(update.passenger_id)
        if passenger is None:
            # Passenger ids are scoped to this booking; an unknown one is not an
            # excuse to reach into another booking's rows.
            continue
        before = {"given_name": passenger.given_name, "family_name": passenger.family_name}
        if update.given_name:
            passenger.given_name = update.given_name
        if update.family_name:
            passenger.family_name = update.family_name
        changes.append(
            {
                "passenger_id": str(passenger.id),
                "before": before,
                "after": {
                    "given_name": passenger.given_name,
                    "family_name": passenger.family_name,
                },
            }
        )

    if changes:
        await audit.record(
            db,
            booking.id,
            AuditEventType.PASSENGER_UPDATED,
            actor_type="user",
            actor_id=user.id,
            from_state=booking.state,
            to_state=booking.state,
            detail={"changes": changes},
        )
    await db.commit()
    await db.refresh(booking)
    return await _to_response(db, booking)


@router.post("/{booking_ref}/cancel")
async def cancel_booking(
    booking: OwnedBooking, user: CurrentUser, request: Request, db: DbSession
) -> dict:
    require_state(booking.state, BookingState.CONFIRMED, BookingState.TICKETED)
    return await booking_saga.cancel(db, booking=booking, user=user, request=request)


@router.get("/{booking_ref}/audit", response_model=list[AuditEntryResponse])
async def booking_audit(booking: OwnedBooking, db: DbSession) -> list[BookingAudit]:
    """The booking's own append-only history, scoped to its owner."""
    return list(
        (
            await db.scalars(
                select(BookingAudit)
                .where(BookingAudit.booking_id == booking.id)
                .order_by(BookingAudit.seq)
            )
        ).all()
    )
