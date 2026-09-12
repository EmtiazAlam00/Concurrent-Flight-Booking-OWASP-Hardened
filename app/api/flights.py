import uuid
from datetime import date, datetime, time, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import Integer, case, func, select

from app.deps import DbSession
from app.domain.models import Airline, Flight, SeatInventory
from app.errors import NotFound
from app.schemas.common import Page
from app.schemas.flights import (
    FlightSummary,
    IataQuery,
    SeatMapResponse,
    SeatResponse,
)
from app.security.ratelimit import rate_limit
from app.services.holds import takeable

router = APIRouter(prefix="/flights", tags=["flights"])

#: Search windows are bounded. "All flights ever" is a table scan a caller
#: should not be able to ask for.
MAX_SEARCH_DAYS_AHEAD = 365


@router.get(
    "/search",
    response_model=Page[FlightSummary],
    dependencies=[Depends(rate_limit("search"))],
)
async def search_flights(
    db: DbSession,
    origin: IataQuery,
    destination: IataQuery,
    departure_date: Annotated[date, Query(description="Departure date (UTC)")],
    page: Annotated[int, Query(ge=1, le=1000)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
) -> Page[FlightSummary]:
    if departure_date > date.today() + timedelta(days=MAX_SEARCH_DAYS_AHEAD):
        raise NotFound("No flights scheduled that far ahead")

    day_start = datetime.combine(departure_date, time.min)
    day_end = day_start + timedelta(days=1)

    base_filters = (
        Flight.src_iata == origin.upper(),
        Flight.dst_iata == destination.upper(),
        Flight.depart_at >= day_start,
        Flight.depart_at < day_end,
    )

    total = int(await db.scalar(select(func.count()).select_from(Flight).where(*base_filters)) or 0)

    # Availability is computed with the same `takeable` predicate the hold path
    # uses, so search can never advertise a seat that holding would reject.
    availability = (
        select(
            SeatInventory.flight_id.label("flight_id"),
            func.sum(case((takeable(), 1), else_=0)).cast(Integer).label("seats_available"),
        )
        .group_by(SeatInventory.flight_id)
        .subquery()
    )

    rows = (
        await db.execute(
            select(Flight, Airline.name, availability.c.seats_available)
            .join(Airline, Airline.iata == Flight.airline_iata)
            .outerjoin(availability, availability.c.flight_id == Flight.id)
            .where(*base_filters)
            .order_by(Flight.depart_at)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).all()

    items = [
        FlightSummary(
            id=flight.id,
            flight_no=flight.flight_no,
            airline_iata=flight.airline_iata,
            airline_name=airline_name,
            src_iata=flight.src_iata,
            dst_iata=flight.dst_iata,
            depart_at=flight.depart_at,
            arrive_at=flight.arrive_at,
            aircraft_type=flight.aircraft_type,
            base_fare=flight.base_fare,
            currency=flight.currency,
            seats_available=int(seats_available or 0),
        )
        for flight, airline_name, seats_available in rows
    ]

    return Page[FlightSummary](
        items=items,
        page=page,
        page_size=page_size,
        total=total,
        has_more=page * page_size < total,
    )


@router.get("/{flight_id}", response_model=FlightSummary)
async def get_flight(flight_id: uuid.UUID, db: DbSession) -> FlightSummary:
    flight = await db.get(Flight, flight_id)
    if flight is None:
        raise NotFound("No such flight")
    available = int(
        await db.scalar(
            select(func.count())
            .select_from(SeatInventory)
            .where(SeatInventory.flight_id == flight_id, takeable())
        )
        or 0
    )
    return FlightSummary(
        id=flight.id,
        flight_no=flight.flight_no,
        airline_iata=flight.airline_iata,
        airline_name=flight.airline.name if flight.airline else None,
        src_iata=flight.src_iata,
        dst_iata=flight.dst_iata,
        depart_at=flight.depart_at,
        arrive_at=flight.arrive_at,
        aircraft_type=flight.aircraft_type,
        base_fare=flight.base_fare,
        currency=flight.currency,
        seats_available=available,
    )


@router.get("/{flight_id}/seats", response_model=SeatMapResponse)
async def seat_map(flight_id: uuid.UUID, db: DbSession) -> SeatMapResponse:
    """The seat map.

    `available` is derived from the same expiry-aware predicate as everything
    else: a seat whose hold lapsed reports as free here without waiting for the
    sweep job to tidy the row.
    """
    flight = await db.get(Flight, flight_id)
    if flight is None:
        raise NotFound("No such flight")

    rows = (
        await db.execute(
            select(SeatInventory, case((takeable(), True), else_=False).label("available"))
            .where(SeatInventory.flight_id == flight_id)
            .order_by(SeatInventory.row_no, SeatInventory.seat_letter)
        )
    ).all()

    seats = [
        SeatResponse(
            seat_no=seat.seat_no,
            row_no=seat.row_no,
            seat_letter=seat.seat_letter,
            cabin=seat.cabin,
            price=seat.price,
            is_exit_row=seat.is_exit_row,
            available=bool(available),
        )
        for seat, available in rows
    ]

    return SeatMapResponse(
        flight_id=flight_id,
        currency=flight.currency,
        total_seats=len(seats),
        available_seats=sum(1 for s in seats if s.available),
        seats=seats,
    )
