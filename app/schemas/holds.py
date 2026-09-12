import uuid
from datetime import datetime
from decimal import Decimal

from app.schemas.common import ResponseModel, StrictModel
from app.schemas.flights import SeatNumber


class HoldRequest(StrictModel):
    flight_id: uuid.UUID
    seat_no: SeatNumber


class HoldResponse(ResponseModel):
    hold_id: uuid.UUID
    flight_id: uuid.UUID
    seat_no: str
    cabin: str
    price: Decimal
    currency: str
    expires_at: datetime
    #: Countdown the dashboard renders. Negative would mean an expired hold, and
    #: an expired hold is simply not a hold — the API clamps at zero.
    seconds_remaining: int
    active: bool
