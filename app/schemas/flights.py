import uuid
from datetime import date, datetime
from decimal import Decimal
from typing import Annotated

from fastapi import Query
from pydantic import Field

from app.schemas.common import ResponseModel

#: IATA codes are exactly three uppercase letters. Constraining the type at the
#: edge means the value reaching SQL cannot be anything else.
IataCode = Annotated[str, Field(min_length=3, max_length=3, pattern=r"^[A-Za-z]{3}$")]
SeatNumber = Annotated[str, Field(min_length=2, max_length=4, pattern=r"^[0-9]{1,3}[A-Za-z]$")]

#: Query-parameter variant. This has to carry its own constraints rather than
#: reusing IataCode: writing `origin: IataCode = Query(...)` makes FastAPI take
#: the Query object as the parameter's metadata and *silently drop* the Field
#: constraints from the annotation — the validation looks present and isn't.
#: Everything here is expressed inside a single Annotated, with no default.
IataQuery = Annotated[
    str,
    Query(
        min_length=3,
        max_length=3,
        pattern=r"^[A-Za-z]{3}$",
        description="IATA airport code",
        examples=["YOW"],
    ),
]


class AirportResponse(ResponseModel):
    iata: str
    name: str
    city: str | None
    country: str | None


class FlightSummary(ResponseModel):
    id: uuid.UUID
    flight_no: str
    airline_iata: str
    airline_name: str | None = None
    src_iata: str
    dst_iata: str
    depart_at: datetime
    arrive_at: datetime
    aircraft_type: str
    base_fare: Decimal
    currency: str
    seats_available: int | None = None


class SeatResponse(ResponseModel):
    seat_no: str
    row_no: int
    seat_letter: str
    cabin: str
    price: Decimal
    is_exit_row: bool
    #: Derived, not the raw column: a held-but-expired seat reports as available,
    #: because that is what it actually is.
    available: bool


class SeatMapResponse(ResponseModel):
    flight_id: uuid.UUID
    currency: str
    total_seats: int
    available_seats: int
    seats: list[SeatResponse]


class FlightSearchQuery(ResponseModel):
    origin: IataCode
    destination: IataCode
    departure_date: date
