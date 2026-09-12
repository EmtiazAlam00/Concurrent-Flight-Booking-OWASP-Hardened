"""Object-level authorization — OWASP API Security #1 (BOLA).

The design rule: **ownership lives in the WHERE clause.** Every booking-scoped
route declares its parameter as `OwnedBooking`, so a handler can never receive a
raw `booking_ref` that nobody checked. Forgetting the check isn't possible
without changing the signature, which means a missing check is a type error
rather than a silent data leak.

Two details that matter more than they look:

* **404, not 403.** Telling an attacker "that booking exists but isn't yours"
  turns the endpoint into an existence oracle and leaks which PNRs are real. An
  unauthorized read is indistinguishable from a nonexistent one.
* **One query, not fetch-then-check.** `SELECT ... WHERE id = :id AND user_id =
  :me` has no window between load and decision, and no chance of a later
  refactor dropping the `if`.

The deliberately vulnerable version of this file lives on the
`demo/bola-vulnerable` branch, together with the exploit test. See SECURITY.md.
"""

import uuid
from typing import Annotated

from fastapi import Depends, Path, Request
from sqlalchemy import select

from app.deps import CurrentUser, DbSession
from app.domain.enums import SecurityEventType, Severity
from app.domain.models import Booking, SeatInventory
from app.errors import NotFound
from app.security.events import record_security_event_bg

BookingRef = Annotated[
    str,
    Path(
        min_length=6,
        max_length=6,
        pattern=r"^[23456789ACDEFGHJKLMNPQRSTUVWXYZ]{6}$",
        description="Booking reference (PNR)",
        examples=["K7R2MQ"],
    ),
]


async def _deny(request: Request, user_id, resource_type: str, resource_id: str) -> None:
    await record_security_event_bg(
        request,
        SecurityEventType.AUTHZ_DENIED,
        Severity.MEDIUM,
        actor_user_id=user_id,
        resource_type=resource_type,
        resource_id=resource_id,
        decision="deny",
        detail={
            "reason": "not_owner_or_missing",
            "note": "responded 404 so the endpoint is not an existence oracle",
        },
    )


async def owned_booking(
    request: Request,
    booking_ref: BookingRef,
    user: CurrentUser,
    db: DbSession,
) -> Booking:
    booking = await db.scalar(
        select(Booking).where(
            Booking.ref == booking_ref.upper(),
            Booking.user_id == user.id,  # <- the authorization, inlined in the query
        )
    )
    if booking is None:
        await _deny(request, user.id, "booking", booking_ref)
        raise NotFound("No such booking")
    return booking


OwnedBooking = Annotated[Booking, Depends(owned_booking)]


async def owned_hold(
    request: Request,
    hold_id: Annotated[uuid.UUID, Path(description="Hold id returned by POST /holds")],
    user: CurrentUser,
    db: DbSession,
) -> SeatInventory:
    """A hold is not a table — it is a state on the contended seat row.

    Ownership is still a WHERE-clause concern. Note that an *expired* hold is
    still returned here so the caller can be told "expired" rather than "gone";
    callers must check `hold_expires_at` themselves.
    """
    seat = await db.scalar(
        select(SeatInventory).where(
            SeatInventory.hold_id == hold_id,
            SeatInventory.held_by_user_id == user.id,
        )
    )
    if seat is None:
        await _deny(request, user.id, "hold", str(hold_id))
        raise NotFound("No such hold")
    return seat


OwnedHold = Annotated[SeatInventory, Depends(owned_hold)]
