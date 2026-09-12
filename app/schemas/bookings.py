import uuid
from datetime import date, datetime
from decimal import Decimal
from typing import Annotated, Any

from pydantic import BeforeValidator, Field, field_validator, model_validator

from app.schemas.common import ResponseModel, StrictModel

#: Opaque gateway token. A raw PAN must never reach this service — that is what
#: keeps it out of PCI-DSS scope. The pattern makes "someone posted a card
#: number" a 422 at the edge rather than a compliance incident.
CardToken = Annotated[
    str, Field(min_length=12, max_length=64, pattern=r"^tok_(test|live)_[A-Za-z0-9]{8,48}$")
]

#: Latin letters incl. common accents, plus the punctuation that appears in real
#: names (O'Neill, Jean-Luc, Jr.). Deliberately does not accept digits or
#: symbols — a passenger name is printed on a boarding pass, not a free-text
#: field, and constraining it here removes a whole class of injection sinks.
NameField = Annotated[
    str,
    Field(min_length=1, max_length=100, pattern=r"^[A-Za-zÀ-ÖØ-öø-ÿ][A-Za-zÀ-ÖØ-öø-ÿ\-'. ]*$"),
]


class PassengerIn(StrictModel):
    given_name: NameField
    family_name: NameField
    dob: date | None = None
    passport_number: Annotated[
        str | None, Field(default=None, min_length=6, max_length=12, pattern=r"^[A-Za-z0-9]+$")
    ]

    @field_validator("dob")
    @classmethod
    def plausible_dob(cls, v: date | None) -> date | None:
        if v is None:
            return v
        if v > date.today() or v.year < 1900:
            raise ValueError("date of birth is not plausible")
        return v


class BookingCreate(StrictModel):
    #: One hold per passenger. Multi-seat bookings are what make deterministic
    #: lock ordering necessary — see app/services/booking_saga.py.
    hold_ids: Annotated[list[uuid.UUID], Field(min_length=1, max_length=6)]
    passengers: Annotated[list[PassengerIn], Field(min_length=1, max_length=6)]
    card_token: CardToken
    contact_email: Annotated[str | None, Field(default=None, max_length=320)] = None

    @model_validator(mode="after")
    def one_seat_per_passenger(self) -> "BookingCreate":
        if len(self.hold_ids) != len(self.passengers):
            raise ValueError("hold_ids and passengers must be the same length")
        if len(set(self.hold_ids)) != len(self.hold_ids):
            raise ValueError("hold_ids must be unique")
        return self


class PassengerUpdate(StrictModel):
    passenger_id: uuid.UUID
    given_name: NameField | None = None
    family_name: NameField | None = None


class BookingPatch(StrictModel):
    """Only passenger details are mutable.

    Seats, price and flight are deliberately immutable after ticketing: changing
    them is a re-booking, which has to go back through the saga (and the
    payment) rather than being an UPDATE.
    """

    passengers: Annotated[list[PassengerUpdate], Field(min_length=1, max_length=6)]


class TicketResponse(ResponseModel):
    e_ticket_no: str
    seat_no: str | None
    passenger_name: str
    issued_at: datetime


class PassengerResponse(ResponseModel):
    id: uuid.UUID
    given_name: str
    family_name: str
    seat_no: str | None = None
    #: Never the full document number, in any response, to any caller.
    passport_last4: str | None = None


class BookingResponse(ResponseModel):
    ref: str
    state: str
    flight_id: uuid.UUID
    flight_no: str | None = None
    src_iata: str | None = None
    dst_iata: str | None = None
    depart_at: datetime | None = None
    total_amount: Decimal
    currency: str
    passengers: list[PassengerResponse]
    tickets: list[TicketResponse] = []
    created_at: datetime


class AuditEntryResponse(ResponseModel):
    seq: int
    event_type: str
    actor_type: str
    from_state: str | None
    to_state: str | None
    detail: dict[str, Any]
    occurred_at: datetime


class SecurityEventResponse(ResponseModel):
    id: int
    occurred_at: datetime
    event_type: str
    severity: str
    actor_user_id: uuid.UUID | None
    actor_email: str | None
    #: Postgres INET comes back from asyncpg as an ipaddress object, not a str.
    ip: Annotated[str | None, BeforeValidator(lambda v: str(v) if v is not None else None)]
    path: str | None
    resource_type: str | None
    resource_id: str | None
    decision: str | None
    detail: dict[str, Any]
