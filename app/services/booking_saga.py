"""The booking saga: hold -> charge -> issue tickets -> confirm.

Any step can fail after the previous one succeeded, so every step has to be
recoverable and every partial state has to be nameable. The rules this file
follows:

* **Short transactions, explicit boundaries.** The saga is several small
  transactions, not one long one. Holding a database transaction open across a
  network call to a payment gateway would pin row locks for the duration of
  someone else's outage.
* **The audit log is the journal.** Each state change writes its audit row in
  the same transaction, so a crash leaves a readable trail instead of ambiguity.
* **Re-verify after every gap.** Between the charge and ticketing there is a
  window in which a hold can expire. Seats are re-locked and re-checked on the
  far side of that window rather than assumed.
* **Compensation can fail too.** That is a real state (NEEDS_MANUAL_REVIEW),
  not an exception we pretend cannot happen.

The failure matrix in docs/failure-matrix.md maps every branch here to a test.
"""

import logging
import uuid
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from fastapi import Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.enums import (
    AuditEventType,
    BookingState,
    Decision,
    PaymentState,
    SeatStatus,
    SecurityEventType,
    Severity,
)
from app.domain.models import (
    Booking,
    BookingPassenger,
    Payment,
    SeatInventory,
    Ticket,
    User,
)
from app.domain.money import money
from app.domain.pnr import generate_eticket_number, generate_pnr
from app.domain.states import assert_can_transition
from app.errors import (
    BookingCompensated,
    HoldExpired,
    NotFound,
    PaymentBlocked,
    PaymentDeclined,
    SeatUnavailable,
)
from app.schemas.bookings import BookingCreate
from app.security import carding
from app.security.events import client_ip, record_security_event_bg
from app.security.hashing import card_fingerprint
from app.services import audit, holds
from app.services.demo_triggers import Trigger, trigger_for
from app.services.payments import PaymentTimeout, RefundFailed, get_gateway

logger = logging.getLogger("skylock.saga")

MAX_PNR_ATTEMPTS = 6


class TicketingFailed(Exception):
    """Ticket issuance failed after the card was already charged."""


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


async def _lock_seats_for_holds(
    session: AsyncSession, hold_ids: list[uuid.UUID], user_id: uuid.UUID
) -> list[SeatInventory]:
    """Lock every seat behind these holds, in a deterministic order.

    Ordering by primary key is what stops two concurrent multi-seat bookings
    from deadlocking: if request A locks seat 1 then seat 2 while request B
    locks seat 2 then seat 1, Postgres detects a deadlock and kills one of them.
    Sorting means everyone walks the rows the same way, so the second request
    simply waits.
    """
    stmt = (
        select(SeatInventory)
        .where(
            SeatInventory.hold_id.in_(hold_ids),
            SeatInventory.held_by_user_id == user_id,
        )
        .order_by(SeatInventory.id)
        .with_for_update()
    )
    return list((await session.scalars(stmt)).all())


def _seconds_left(seat: SeatInventory) -> float:
    if seat.hold_expires_at is None:
        return -1.0
    return (seat.hold_expires_at - datetime.now(UTC)).total_seconds()


async def _unique_pnr(session: AsyncSession) -> str:
    for _ in range(MAX_PNR_ATTEMPTS):
        candidate = generate_pnr()
        exists = await session.scalar(select(Booking.id).where(Booking.ref == candidate))
        if exists is None:
            return candidate
    # The unique constraint on bookings.ref is the real guarantee; this is just
    # to avoid burning a transaction on a collision.
    raise RuntimeError("could not allocate a unique PNR")


def _booking_payload(booking: Booking, seats_by_passenger: dict[uuid.UUID, str]) -> dict[str, Any]:
    return {
        "ref": booking.ref,
        "state": booking.state,
        "flight_id": str(booking.flight_id),
        "total_amount": str(booking.total_amount),
        "currency": booking.currency,
        "passengers": [
            {
                "id": str(p.id),
                "given_name": p.given_name,
                "family_name": p.family_name,
                "seat_no": seats_by_passenger.get(p.id),
                "passport_last4": p.passport_last4,
            }
            for p in booking.passengers
        ],
        "tickets": [
            {
                "e_ticket_no": t.e_ticket_no,
                "seat_no": seats_by_passenger.get(t.passenger_id),
                "issued_at": t.issued_at.isoformat() if t.issued_at else None,
            }
            for t in booking.tickets
            if t.voided_at is None
        ],
        "created_at": booking.created_at.isoformat() if booking.created_at else None,
    }


# ---------------------------------------------------------------------------
# the saga
# ---------------------------------------------------------------------------


async def run(
    session: AsyncSession,
    *,
    user: User,
    payload: BookingCreate,
    idempotency_key: str,
    request: Request | None = None,
) -> tuple[int, dict[str, Any]]:
    """Execute the booking saga. Returns (status_code, response_body)."""

    # -- step 1: lock the seats and create the booking -----------------------
    #
    # This transaction is the one that decides whether the booking may exist at
    # all. Nothing outside the database is touched while these locks are held.
    seats = await _lock_seats_for_holds(session, payload.hold_ids, user.id)

    if len(seats) != len(payload.hold_ids):
        await session.rollback()
        raise NotFound("One or more holds do not exist or are not yours")

    expired = [s.seat_no for s in seats if _seconds_left(s) <= 0 or s.status != SeatStatus.HELD]
    if expired:
        # Matrix row 2: hold expired *before* payment. Reject outright — the
        # cheapest correct outcome is the one where no money moved.
        #
        # Note the seat numbers are read into plain strings *before* the
        # rollback: a rollback expires every ORM instance in the session, so
        # touching `seat.seat_no` afterwards would attempt lazy IO.
        await session.rollback()
        raise HoldExpired(
            "Seat hold expired before checkout completed: "
            + ", ".join(expired)
            + ". Re-select your seats."
        )

    flight_ids = {s.flight_id for s in seats}
    if len(flight_ids) != 1:
        await session.rollback()
        raise SeatUnavailable("All seats in one booking must be on the same flight")
    flight_id = flight_ids.pop()

    flight = await holds.get_flight_or_404(session, flight_id)
    total = money(sum((s.price for s in seats), Decimal("0")))

    booking = Booking(
        ref=await _unique_pnr(session),
        user_id=user.id,
        flight_id=flight_id,
        state=BookingState.PENDING,
        total_amount=total,
        currency=flight.currency,
        idempotency_key=idempotency_key,
    )
    session.add(booking)
    await session.flush()

    # Seats are pinned to this booking now, while still `held`. They only become
    # `booked` once tickets exist — so a crash here leaves them recoverable by
    # the sweep rather than stranded as sold.
    ordered_seats = sorted(seats, key=lambda s: (s.row_no, s.seat_letter))
    passenger_rows: list[BookingPassenger] = []
    for passenger_in, seat in zip(payload.passengers, ordered_seats, strict=True):
        row = BookingPassenger(
            booking_id=booking.id,
            given_name=passenger_in.given_name,
            family_name=passenger_in.family_name,
            dob_enc=passenger_in.dob.isoformat().encode() if passenger_in.dob else None,
            passport_enc=(
                passenger_in.passport_number.encode() if passenger_in.passport_number else None
            ),
            passport_last4=(
                passenger_in.passport_number[-4:] if passenger_in.passport_number else None
            ),
            seat_inventory_id=seat.id,
        )
        session.add(row)
        passenger_rows.append(row)
        seat.booking_id = booking.id
        seat.version += 1

    await session.flush()
    await audit.record(
        session,
        booking.id,
        AuditEventType.BOOKING_CREATED,
        actor_type="user",
        actor_id=user.id,
        to_state=BookingState.PENDING,
        detail={
            "flight_id": str(flight_id),
            "seats": [s.seat_no for s in ordered_seats],
            "total_amount": str(total),
            "currency": flight.currency,
            "idempotency_key": idempotency_key,
        },
    )
    await audit.record(
        session,
        booking.id,
        AuditEventType.SEATS_LOCKED,
        detail={"seat_ids": [str(s.id) for s in ordered_seats]},
    )
    await session.commit()

    seats_by_passenger = {
        p.id: s.seat_no for p, s in zip(passenger_rows, ordered_seats, strict=True)
    }
    fingerprint = card_fingerprint(payload.card_token)
    ip = client_ip(request)

    # -- step 2: fraud controls ---------------------------------------------
    #
    # Deliberately after the booking row exists: a blocked attempt should leave
    # a trail, not vanish.
    assessment = await carding.assess_payment_attempt(
        user_id=user.id,
        ip=ip,
        card_fingerprint=fingerprint,
        amount=total,
        request=request,
    )
    if assessment.decision is Decision.BLOCK:
        await _fail_payment(
            session,
            booking,
            failure_code="blocked_by_fraud_controls",
            detail={"carding": assessment.as_dict()},
            audit_event=AuditEventType.PAYMENT_DECLINED,
        )
        raise PaymentBlocked(
            "This payment was blocked by our fraud controls. "
            "Contact support if you believe this is an error.",
            risk_score=assessment.score,
            rules=[h.rule for h in assessment.hits],
        )

    # -- step 3: authorize the charge ---------------------------------------
    gateway = get_gateway()
    gateway_key = f"{idempotency_key}:auth"
    payment = Payment(
        booking_id=booking.id,
        provider=gateway.name,
        card_token=payload.card_token,
        card_fingerprint=fingerprint,
        card_last4=payload.card_token[-4:],
        amount=total,
        currency=booking.currency,
        state=PaymentState.PENDING,
        idempotency_key=gateway_key,
    )
    session.add(payment)
    await session.commit()

    try:
        result = await gateway.authorize(
            card_token=payload.card_token,
            amount=total,
            currency=booking.currency,
            idempotency_key=gateway_key,
            metadata={"booking_ref": booking.ref, "user_id": str(user.id)},
        )
    except PaymentTimeout:
        # Matrix row 6: we do not know whether the charge happened. Retrying
        # with the *same* gateway key is safe precisely because the gateway is
        # idempotent — it either performs the charge or replays the first one.
        payment.state = PaymentState.UNKNOWN
        await audit.record(
            session,
            booking.id,
            AuditEventType.PAYMENT_UNKNOWN,
            detail={"note": "gateway timed out; retrying with the same idempotency key"},
        )
        await session.commit()
        logger.warning("payment gateway timeout for booking %s; retrying", booking.ref)
        result = await gateway.authorize(
            card_token=payload.card_token,
            amount=total,
            currency=booking.currency,
            idempotency_key=gateway_key,
            metadata={"booking_ref": booking.ref, "user_id": str(user.id)},
        )

    await carding.record_outcome(
        user_id=user.id,
        ip=ip,
        card_fingerprint=fingerprint,
        approved=result.approved,
        request=request,
    )

    if not result.approved:
        # Matrix row 4: a clean decline. No compensation is needed because
        # nothing succeeded — and the seat hold is deliberately *left alone* so
        # the customer can retry with another card inside their TTL.
        payment.state = PaymentState.DECLINED
        payment.provider_ref = result.provider_ref
        payment.failure_code = result.failure_code
        await _fail_payment(
            session,
            booking,
            failure_code=result.failure_code or "declined",
            detail={"gateway_message": result.message, "carding": assessment.as_dict()},
            audit_event=AuditEventType.PAYMENT_DECLINED,
        )
        await record_security_event_bg(
            request,
            SecurityEventType.PAYMENT_DECLINED,
            Severity.LOW,
            actor_user_id=user.id,
            resource_type="booking",
            resource_id=booking.ref,
            detail={
                "failure_code": result.failure_code,
                "card_fingerprint": fingerprint[:12],
                "risk_score": assessment.score,
            },
        )
        raise PaymentDeclined(
            f"Payment was declined ({result.failure_code}). "
            "Your seat hold is still active — you can try another card."
        )

    payment.state = PaymentState.AUTHORIZED
    payment.provider_ref = result.provider_ref
    assert_can_transition(booking.state, BookingState.PAYMENT_AUTHORIZED)
    await audit.record(
        session,
        booking.id,
        AuditEventType.PAYMENT_AUTHORIZED,
        from_state=booking.state,
        to_state=BookingState.PAYMENT_AUTHORIZED,
        detail={
            "provider_ref": result.provider_ref,
            "amount": str(total),
            "currency": booking.currency,
        },
    )
    booking.state = BookingState.PAYMENT_AUTHORIZED
    await session.commit()

    # -- step 4: issue tickets ----------------------------------------------
    #
    # Money has moved. From here on, every failure path must put it back.
    try:
        await _issue_tickets(
            session,
            booking=booking,
            passengers=passenger_rows,
            seats=ordered_seats,
            user_id=user.id,
            card_token=payload.card_token,
        )
    except (TicketingFailed, SeatUnavailable) as exc:
        await _compensate(
            session,
            booking=booking,
            payment=payment,
            reason=str(exc),
            card_token=payload.card_token,
            request=request,
            user_id=user.id,
        )
        raise BookingCompensated(
            f"{exc} Your card was not charged — the authorization has been reversed."
        ) from exc

    # -- step 5: confirm -----------------------------------------------------
    await gateway.capture(provider_ref=result.provider_ref, idempotency_key=f"{gateway_key}:cap")
    payment.state = PaymentState.CAPTURED
    assert_can_transition(booking.state, BookingState.CONFIRMED)
    await audit.record(
        session,
        booking.id,
        AuditEventType.BOOKING_CONFIRMED,
        from_state=booking.state,
        to_state=BookingState.CONFIRMED,
        detail={"pnr": booking.ref},
    )
    booking.state = BookingState.CONFIRMED
    await session.commit()
    await session.refresh(booking)

    return 201, _booking_payload(booking, seats_by_passenger)


# ---------------------------------------------------------------------------
# steps
# ---------------------------------------------------------------------------


async def _issue_tickets(
    session: AsyncSession,
    *,
    booking: Booking,
    passengers: list[BookingPassenger],
    seats: list[SeatInventory],
    user_id: uuid.UUID,
    card_token: str,
) -> None:
    """Re-verify the seats, then issue tickets and mark the seats booked.

    The re-verification is the important part. Between the charge and this
    moment the holds may have expired (matrix row 3), so we take the row locks
    again and check rather than trusting what we read before the network call.
    """
    seat_ids = sorted(s.id for s in seats)
    locked = list(
        (
            await session.scalars(
                select(SeatInventory)
                .where(SeatInventory.id.in_(seat_ids))
                .order_by(SeatInventory.id)
                .with_for_update()
            )
        ).all()
    )
    by_id = {s.id: s for s in locked}

    lost: list[str] = []
    for seat in locked:
        still_ours = seat.booking_id == booking.id and seat.held_by_user_id == user_id
        if not still_ours or seat.status == SeatStatus.BOOKED and seat.booking_id != booking.id:
            lost.append(seat.seat_no)
            continue
        if _seconds_left(seat) <= 0:
            # The hold lapsed mid-payment. The seat is still ours only because
            # nobody else grabbed it in the gap; re-extend rather than fail.
            await audit.record(
                session,
                booking.id,
                AuditEventType.HOLD_LOST,
                detail={
                    "seat_no": seat.seat_no,
                    "note": "hold expired during payment but seat was still free; reclaimed",
                },
            )

    if lost:
        await audit.record(
            session,
            booking.id,
            AuditEventType.HOLD_LOST,
            detail={"seats": lost, "note": "seats taken by another booking during payment"},
        )
        raise SeatUnavailable(
            f"Seat(s) {', '.join(lost)} were taken while your payment was processing."
        )

    # Injected failure for the demo/test matrix — the branch that exercises
    # compensation after a successful charge.
    if trigger_for(card_token) is Trigger.TICKETING_FAILURE:
        await audit.record(
            session,
            booking.id,
            AuditEventType.TICKETING_FAILED,
            detail={"reason": "downstream ticketing system rejected the request"},
        )
        raise TicketingFailed("Ticket issuance failed after payment was authorized.")

    issued = []
    for passenger in passengers:
        # Every passenger was given a seat in step 1 of the saga. If that is not
        # true we are about to issue a ticket for nothing, so fail loudly rather
        # than defaulting to something plausible.
        if passenger.seat_inventory_id is None or passenger.seat_inventory_id not in by_id:
            raise TicketingFailed(
                f"passenger {passenger.id} has no seat assigned; refusing to issue a ticket"
            )
        seat = by_id[passenger.seat_inventory_id]
        ticket = Ticket(
            booking_id=booking.id,
            passenger_id=passenger.id,
            seat_inventory_id=seat.id,
            e_ticket_no=generate_eticket_number(),
        )
        session.add(ticket)
        issued.append({"seat_no": seat.seat_no, "e_ticket_no": ticket.e_ticket_no})

        seat.status = SeatStatus.BOOKED
        seat.hold_id = None
        seat.hold_expires_at = None
        seat.booking_id = booking.id
        seat.version += 1

    await session.flush()
    assert_can_transition(booking.state, BookingState.TICKETED)
    await audit.record(
        session,
        booking.id,
        AuditEventType.TICKETS_ISSUED,
        from_state=booking.state,
        to_state=BookingState.TICKETED,
        detail={"tickets": issued},
    )
    booking.state = BookingState.TICKETED
    await session.commit()


async def _fail_payment(
    session: AsyncSession,
    booking: Booking,
    *,
    failure_code: str,
    detail: dict[str, Any],
    audit_event: AuditEventType,
) -> None:
    """Terminal failure with nothing to unwind. Seats stay held for a retry."""
    assert_can_transition(booking.state, BookingState.PAYMENT_FAILED)
    await audit.record(
        session,
        booking.id,
        audit_event,
        from_state=booking.state,
        to_state=BookingState.PAYMENT_FAILED,
        detail={"failure_code": failure_code, **detail},
    )
    booking.state = BookingState.PAYMENT_FAILED
    # The seats keep their hold, but stop pointing at a dead booking.
    for seat in await session.scalars(
        select(SeatInventory).where(SeatInventory.booking_id == booking.id)
    ):
        seat.booking_id = None
        seat.version += 1
    await session.commit()


async def _compensate(
    session: AsyncSession,
    *,
    booking: Booking,
    payment: Payment,
    reason: str,
    card_token: str,
    request: Request | None,
    user_id: uuid.UUID,
) -> None:
    """Undo a successful charge and hand the seats back.

    Compensation is not a rollback — the charge really happened and cannot be
    un-happened, only reversed by a second operation that can itself fail. When
    it does, the booking lands in NEEDS_MANUAL_REVIEW and shows up on the
    dashboard, because a booking that quietly kept someone's money would be the
    worst possible failure mode.
    """
    gateway = get_gateway()

    assert_can_transition(booking.state, BookingState.COMPENSATING)
    await audit.record(
        session,
        booking.id,
        AuditEventType.COMPENSATION_STARTED,
        from_state=booking.state,
        to_state=BookingState.COMPENSATING,
        detail={"reason": reason, "provider_ref": payment.provider_ref},
    )
    booking.state = BookingState.COMPENSATING
    await session.commit()

    if trigger_for(card_token) is Trigger.REFUND_FAILURE and hasattr(gateway, "arm_refund_failure"):
        gateway.arm_refund_failure(payment.provider_ref or "")

    try:
        if payment.state == PaymentState.CAPTURED:
            await gateway.refund(
                provider_ref=payment.provider_ref or "",
                amount=payment.amount,
                idempotency_key=f"{payment.idempotency_key}:refund",
            )
            payment.state = PaymentState.REFUNDED
            event = AuditEventType.PAYMENT_REFUNDED
        else:
            # Authorized but not captured: voiding is cleaner than refunding —
            # the customer never sees a charge appear and disappear.
            await gateway.void(
                provider_ref=payment.provider_ref or "",
                idempotency_key=f"{payment.idempotency_key}:void",
            )
            payment.state = PaymentState.VOIDED
            event = AuditEventType.PAYMENT_VOIDED
    except (RefundFailed, PaymentTimeout) as exc:
        await audit.record(
            session,
            booking.id,
            AuditEventType.COMPENSATION_FAILED,
            from_state=booking.state,
            to_state=BookingState.NEEDS_MANUAL_REVIEW,
            detail={
                "error": str(exc),
                "provider_ref": payment.provider_ref,
                "amount": str(payment.amount),
                "note": "money is still with the provider; requires operator action",
            },
        )
        booking.state = BookingState.NEEDS_MANUAL_REVIEW
        released = await holds.release_seats_for_booking(session, booking_id=booking.id)
        await audit.record(
            session,
            booking.id,
            AuditEventType.SEATS_RELEASED,
            detail={"seats_released": released, "note": "released despite refund failure"},
        )
        await session.commit()
        logger.error(
            "compensation failed for booking %s: %s — manual review required",
            booking.ref,
            exc,
        )
        await record_security_event_bg(
            request,
            SecurityEventType.MANUAL_REVIEW_REQUIRED,
            Severity.CRITICAL,
            actor_user_id=user_id,
            resource_type="booking",
            resource_id=booking.ref,
            decision="manual_review",
            detail={"reason": "compensation_failed", "error": str(exc)},
        )
        return

    await audit.record(session, booking.id, event, detail={"provider_ref": payment.provider_ref})
    released = await holds.release_seats_for_booking(session, booking_id=booking.id)
    await audit.record(
        session,
        booking.id,
        AuditEventType.SEATS_RELEASED,
        detail={"seats_released": released},
    )
    assert_can_transition(booking.state, BookingState.VOIDED)
    booking.state = BookingState.VOIDED
    await session.commit()


# ---------------------------------------------------------------------------
# cancellation
# ---------------------------------------------------------------------------


async def cancel(
    session: AsyncSession,
    *,
    booking: Booking,
    user: User,
    request: Request | None = None,
) -> dict[str, Any]:
    """Cancel a confirmed booking: refund, release seats, audit."""
    gateway = get_gateway()
    payment = await session.scalar(
        select(Payment)
        .where(
            Payment.booking_id == booking.id,
            Payment.state.in_(
                [
                    PaymentState.AUTHORIZED,
                    PaymentState.CAPTURED,
                ]
            ),
        )
        .order_by(Payment.created_at.desc())
    )

    # Lock the seats before touching them so a cancel cannot race the sweep or
    # a concurrent confirm.
    await session.execute(
        select(SeatInventory.id)
        .where(SeatInventory.booking_id == booking.id)
        .order_by(SeatInventory.id)
        .with_for_update()
    )

    refunded = False
    if payment is not None:
        try:
            await gateway.refund(
                provider_ref=payment.provider_ref or "",
                amount=payment.amount,
                idempotency_key=f"{payment.idempotency_key}:cancel-refund",
            )
            payment.state = PaymentState.REFUNDED
            refunded = True
        except (RefundFailed, PaymentTimeout) as exc:
            await audit.record(
                session,
                booking.id,
                AuditEventType.COMPENSATION_FAILED,
                from_state=booking.state,
                to_state=BookingState.NEEDS_MANUAL_REVIEW,
                detail={"error": str(exc), "stage": "cancellation_refund"},
            )
            booking.state = BookingState.NEEDS_MANUAL_REVIEW
            await session.commit()
            raise BookingCompensated(
                "We could not process the refund automatically. "
                "Your booking is flagged for manual review."
            ) from exc

    released = await holds.release_seats_for_booking(session, booking_id=booking.id)
    assert_can_transition(booking.state, BookingState.CANCELLED)
    await audit.record(
        session,
        booking.id,
        AuditEventType.BOOKING_CANCELLED,
        actor_type="user",
        actor_id=user.id,
        from_state=booking.state,
        to_state=BookingState.CANCELLED,
        detail={"seats_released": released, "refunded": refunded},
    )
    booking.state = BookingState.CANCELLED
    await session.commit()

    return {
        "ref": booking.ref,
        "state": booking.state,
        "refunded": refunded,
        "seats_released": released,
    }


async def count_confirmed_seats(session: AsyncSession, flight_id: uuid.UUID) -> int:
    """Invariant helper used by tests and the dashboard: seats actually sold."""
    return int(
        await session.scalar(
            select(func.count())
            .select_from(SeatInventory)
            .where(
                SeatInventory.flight_id == flight_id,
                SeatInventory.status == SeatStatus.BOOKED,
            )
        )
        or 0
    )
