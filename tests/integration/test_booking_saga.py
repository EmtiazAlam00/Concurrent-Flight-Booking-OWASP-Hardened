"""The failure matrix, one test per row. See docs/failure-matrix.md.

Each test drives a real HTTP request against a real Postgres, and asserts on
both the response *and* the state the database was left in — because "returned
409" and "left the seat correctly released" are different claims.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select, text, update

from app.db import SessionLocal
from app.domain.enums import BookingState, PaymentState, SeatStatus
from app.domain.models import Booking, BookingAudit, Payment, SeatInventory, Ticket
from app.services.payments import get_gateway
from tests.conftest import (
    APPROVE_TOKEN,
    DECLINE_TOKEN,
    TICKETING_FAILURE_TOKEN,
    TIMEOUT_TOKEN,
    book,
    booking_body,
    hold_seat,
)

pytestmark = pytest.mark.integration


async def _seat(db, flight_id, seat_no) -> SeatInventory:
    return await db.scalar(
        select(SeatInventory).where(
            SeatInventory.flight_id == flight_id, SeatInventory.seat_no == seat_no
        )
    )


async def _audit_events(db, ref: str) -> list[str]:
    booking = await db.scalar(select(Booking).where(Booking.ref == ref))
    rows = list(
        (
            await db.scalars(
                select(BookingAudit)
                .where(BookingAudit.booking_id == booking.id)
                .order_by(BookingAudit.seq)
            )
        ).all()
    )
    return [r.event_type for r in rows]


async def _expire_hold(db, flight_id, seat_no) -> None:
    """Push a hold's expiry into the past without touching anything else.

    This is how the "hold expired" branches are tested deterministically —
    waiting ten minutes is not a test.
    """
    await db.execute(
        update(SeatInventory)
        .where(SeatInventory.flight_id == flight_id, SeatInventory.seat_no == seat_no)
        .values(hold_expires_at=datetime.now(UTC) - timedelta(seconds=1))
    )
    await db.commit()


class TestHappyPath:
    async def test_books_confirms_and_issues_a_ticket(self, client, user, make_flight, db):
        flight = await make_flight(seats=4)
        hold = await hold_seat(client, user, flight.id, flight.seat_numbers[0])

        response = await book(client, user, [hold])
        assert response.status_code == 201, response.text
        body = response.json()

        assert body["state"] == BookingState.CONFIRMED
        assert len(body["ref"]) == 6
        assert len(body["tickets"]) == 1
        assert body["tickets"][0]["seat_no"] == flight.seat_numbers[0]
        assert body["total_amount"] == "250.00"
        # Full passport number must never appear in a response.
        assert body["passengers"][0]["passport_last4"] == "4567"
        assert "AB1234567" not in response.text

        seat = await _seat(db, flight.id, flight.seat_numbers[0])
        assert seat.status == SeatStatus.BOOKED
        assert seat.hold_id is None and seat.hold_expires_at is None

    async def test_audit_trail_is_complete_and_gap_free(self, client, user, make_flight, db):
        flight = await make_flight(seats=4)
        hold = await hold_seat(client, user, flight.id, flight.seat_numbers[0])
        ref = (await book(client, user, [hold])).json()["ref"]

        booking = await db.scalar(select(Booking).where(Booking.ref == ref))
        rows = list(
            (
                await db.scalars(
                    select(BookingAudit)
                    .where(BookingAudit.booking_id == booking.id)
                    .order_by(BookingAudit.seq)
                )
            ).all()
        )
        assert [r.seq for r in rows] == list(range(1, len(rows) + 1)), "seq must be gap-free"
        assert [r.event_type for r in rows] == [
            "BOOKING_CREATED",
            "SEATS_LOCKED",
            "PAYMENT_AUTHORIZED",
            "TICKETS_ISSUED",
            "BOOKING_CONFIRMED",
        ]

    async def test_multi_seat_booking(self, client, user, make_flight, db):
        flight = await make_flight(seats=6)
        holds = [await hold_seat(client, user, flight.id, seat) for seat in flight.seat_numbers[:3]]
        body = booking_body(holds)
        body["passengers"] = [
            {"given_name": "Ada", "family_name": "Lovelace"},
            {"given_name": "Grace", "family_name": "Hopper"},
            {"given_name": "Katherine", "family_name": "Johnson"},
        ]
        response = await book(client, user, holds, body=body)

        assert response.status_code == 201, response.text
        assert response.json()["total_amount"] == "750.00"
        assert len({t["e_ticket_no"] for t in response.json()["tickets"]}) == 3


class TestMatrixRow2HoldExpiredBeforePayment:
    async def test_rejected_with_no_charge(self, client, user, make_flight, db):
        flight = await make_flight(seats=4)
        hold = await hold_seat(client, user, flight.id, flight.seat_numbers[0])
        await _expire_hold(db, flight.id, flight.seat_numbers[0])

        response = await book(client, user, [hold])

        assert response.status_code == 409
        assert response.json()["code"] == "hold_expired"

        # The cheapest correct outcome: no booking, no payment, no charge.
        assert (
            await db.scalar(
                select(func.count()).select_from(Booking).where(Booking.user_id == user.id)
            )
            == 0
        )
        assert get_gateway().authorization_count() == 0


class TestMatrixRow4PaymentDeclined:
    async def test_402_and_hold_survives_for_a_retry(self, client, user, make_flight, db):
        flight = await make_flight(seats=4)
        seat_no = flight.seat_numbers[0]
        hold = await hold_seat(client, user, flight.id, seat_no)

        response = await book(client, user, [hold], card_token=DECLINE_TOKEN)

        assert response.status_code == 402
        assert response.json()["code"] == "payment_declined"

        booking = await db.scalar(select(Booking).where(Booking.user_id == user.id))
        assert booking.state == BookingState.PAYMENT_FAILED

        # The seat is still held by this user: they can retry with another card
        # inside their remaining TTL. Releasing it here would be hostile.
        await db.refresh(await _seat(db, flight.id, seat_no))
        seat = await _seat(db, flight.id, seat_no)
        assert seat.status == SeatStatus.HELD
        assert seat.held_by_user_id == user.id
        assert seat.booking_id is None

    async def test_retry_with_a_good_card_succeeds(self, client, user, make_flight, db):
        flight = await make_flight(seats=4)
        hold = await hold_seat(client, user, flight.id, flight.seat_numbers[0])

        declined = await book(client, user, [hold], card_token=DECLINE_TOKEN)
        assert declined.status_code == 402

        # New idempotency key: this is a genuinely new attempt, not a retry.
        retried = await book(client, user, [hold], card_token=APPROVE_TOKEN)
        assert retried.status_code == 201, retried.text
        assert retried.json()["state"] == BookingState.CONFIRMED


class TestMatrixRow5TicketingFailsAfterCharge:
    async def test_compensates_and_releases_the_seat(self, client, user, make_flight, db):
        flight = await make_flight(seats=4)
        seat_no = flight.seat_numbers[0]
        hold = await hold_seat(client, user, flight.id, seat_no)

        response = await book(client, user, [hold], card_token=TICKETING_FAILURE_TOKEN)

        assert response.status_code == 409
        assert response.json()["code"] == "booking_compensated"

        booking = await db.scalar(select(Booking).where(Booking.user_id == user.id))
        assert booking.state == BookingState.VOIDED

        payment = await db.scalar(select(Payment).where(Payment.booking_id == booking.id))
        assert payment.state == PaymentState.VOIDED
        assert get_gateway().was_voided(payment.provider_ref)

        # The seat goes back to inventory — the customer's money and the
        # airline's seat both end up where they started.
        seat = await _seat(db, flight.id, seat_no)
        assert seat.status == SeatStatus.AVAILABLE
        assert seat.booking_id is None and seat.held_by_user_id is None

        assert (
            await db.scalar(
                select(func.count()).select_from(Ticket).where(Ticket.booking_id == booking.id)
            )
            == 0
        )

        events = await _audit_events(db, booking.ref)
        assert "TICKETING_FAILED" in events
        assert "COMPENSATION_STARTED" in events
        assert "PAYMENT_VOIDED" in events
        assert "SEATS_RELEASED" in events

    async def test_the_seat_is_immediately_bookable_again(self, client, user, make_flight):
        flight = await make_flight(seats=2)
        seat_no = flight.seat_numbers[0]

        hold = await hold_seat(client, user, flight.id, seat_no)
        assert (
            await book(client, user, [hold], card_token=TICKETING_FAILURE_TOKEN)
        ).status_code == 409

        hold2 = await hold_seat(client, user, flight.id, seat_no)
        assert (await book(client, user, [hold2], card_token=APPROVE_TOKEN)).status_code == 201


class TestMatrixRow6GatewayTimeout:
    async def test_retried_with_the_same_key_and_charged_once(self, client, user, make_flight, db):
        flight = await make_flight(seats=4)
        hold = await hold_seat(client, user, flight.id, flight.seat_numbers[0])

        response = await book(client, user, [hold], card_token=TIMEOUT_TOKEN)

        # The saga absorbs the timeout: it retries with the same gateway
        # idempotency key rather than guessing whether the charge happened.
        assert response.status_code == 201, response.text
        assert response.json()["state"] == BookingState.CONFIRMED

        # Exactly one authorization exists, despite two calls.
        assert get_gateway().authorization_count() == 1

        events = await _audit_events(db, response.json()["ref"])
        assert "PAYMENT_UNKNOWN" in events, "the ambiguous state must be journalled"
        assert events.index("PAYMENT_UNKNOWN") < events.index("PAYMENT_AUTHORIZED")


class TestMatrixRow7CompensationFails:
    async def test_lands_in_needs_manual_review(self, client, user, make_flight, db):
        """The worst case, made visible instead of hidden.

        The charge succeeded, ticketing failed, and the reversal *also* failed.
        The money is still with the provider, so the booking must not be quietly
        marked as failed — it needs a human.
        """
        flight = await make_flight(seats=4)
        seat_no = flight.seat_numbers[0]
        hold = await hold_seat(client, user, flight.id, seat_no)

        gateway = get_gateway()
        original_authorize = gateway.authorize

        # Arm both behaviours: ticketing fails, and so does the reversal.
        async def failing_refund(**kwargs):
            from app.services.payments import RefundFailed

            raise RefundFailed("provider rejected the reversal")

        gateway.void = failing_refund  # type: ignore[method-assign]
        try:
            response = await book(client, user, [hold], card_token=TICKETING_FAILURE_TOKEN)
        finally:
            del gateway.void
            gateway.authorize = original_authorize

        assert response.status_code == 409

        booking = await db.scalar(select(Booking).where(Booking.user_id == user.id))
        assert booking.state == BookingState.NEEDS_MANUAL_REVIEW

        events = await _audit_events(db, booking.ref)
        assert "COMPENSATION_FAILED" in events

        # The seat is still handed back — the customer should not lose the seat
        # *and* the money while an operator sorts it out.
        seat = await _seat(db, flight.id, seat_no)
        assert seat.status == SeatStatus.AVAILABLE


class TestMatrixRow8And9Idempotency:
    async def test_identical_retry_replays_the_same_booking(self, client, user, make_flight, db):
        flight = await make_flight(seats=4)
        hold = await hold_seat(client, user, flight.id, flight.seat_numbers[0])
        key = str(uuid.uuid4())

        first = await book(client, user, [hold], idempotency_key=key)
        second = await book(client, user, [hold], idempotency_key=key)

        assert first.status_code == second.status_code == 201
        assert first.json()["ref"] == second.json()["ref"]
        assert second.headers.get("Idempotency-Replayed") == "true"

        # One booking, one ticket, one charge.
        assert (
            await db.scalar(
                select(func.count()).select_from(Booking).where(Booking.user_id == user.id)
            )
            == 1
        )
        assert get_gateway().authorization_count() == 1

    async def test_same_key_different_body_is_422(self, client, user, make_flight):
        flight = await make_flight(seats=4)
        hold = await hold_seat(client, user, flight.id, flight.seat_numbers[0])
        key = str(uuid.uuid4())

        first = await book(client, user, [hold], idempotency_key=key)
        # Assert the setup separately from the behaviour under test. If the first
        # booking ever fails, the message should say so rather than surfacing as
        # a confusing "expected 422, got 409" on the second call.
        assert first.status_code == 201, f"setup booking failed: {first.status_code} {first.text}"

        different = booking_body([hold])
        different["passengers"][0]["given_name"] = "Grace"
        response = await book(client, user, [hold], idempotency_key=key, body=different)

        assert response.status_code == 422, response.text
        assert response.json()["code"] == "idempotency_key_reused"

    async def test_a_declined_attempt_replays_as_declined(self, client, user, make_flight, db):
        """A retry must not turn a decline into a second charge attempt."""
        flight = await make_flight(seats=4)
        hold = await hold_seat(client, user, flight.id, flight.seat_numbers[0])
        key = str(uuid.uuid4())

        first = await book(client, user, [hold], card_token=DECLINE_TOKEN, idempotency_key=key)
        second = await book(client, user, [hold], card_token=DECLINE_TOKEN, idempotency_key=key)

        assert first.status_code == second.status_code == 402
        assert second.json()["code"] == "payment_declined"
        assert get_gateway().authorization_count() == 1

    async def test_missing_idempotency_key_is_rejected(self, client, user, make_flight):
        flight = await make_flight(seats=4)
        hold = await hold_seat(client, user, flight.id, flight.seat_numbers[0])
        response = await client.post("/bookings", headers=user.headers, json=booking_body([hold]))
        assert response.status_code == 422

    async def test_idempotency_is_scoped_per_user(self, client, user, other_user, make_flight):
        """Two users may legitimately pick the same key; they must not collide."""
        flight = await make_flight(seats=4)
        hold_a = await hold_seat(client, user, flight.id, flight.seat_numbers[0])
        hold_b = await hold_seat(client, other_user, flight.id, flight.seat_numbers[1])
        key = "shared-key-00000001"

        first = await book(client, user, [hold_a], idempotency_key=key)
        second = await book(client, other_user, [hold_b], idempotency_key=key)

        assert first.status_code == 201 and second.status_code == 201
        assert first.json()["ref"] != second.json()["ref"]


class TestOwnershipOfHolds:
    async def test_cannot_book_someone_elses_hold(self, client, user, other_user, make_flight):
        flight = await make_flight(seats=4)
        victim_hold = await hold_seat(client, user, flight.id, flight.seat_numbers[0])

        response = await book(client, other_user, [victim_hold])

        assert response.status_code == 404
        assert response.json()["code"] == "not_found"

    async def test_seats_must_be_on_the_same_flight(self, client, user, make_flight):
        first, second = await make_flight(seats=2), await make_flight(seats=2)
        holds = [
            await hold_seat(client, user, first.id, first.seat_numbers[0]),
            await hold_seat(client, user, second.id, second.seat_numbers[0]),
        ]
        body = booking_body(holds)
        body["passengers"] = [
            {"given_name": "Ada", "family_name": "Lovelace"},
            {"given_name": "Grace", "family_name": "Hopper"},
        ]
        response = await book(client, user, holds, body=body)
        assert response.status_code == 409


class TestCancellation:
    async def test_refunds_and_releases(self, client, user, make_flight, db):
        flight = await make_flight(seats=4)
        seat_no = flight.seat_numbers[0]
        hold = await hold_seat(client, user, flight.id, seat_no)
        ref = (await book(client, user, [hold])).json()["ref"]

        response = await client.post(f"/bookings/{ref}/cancel", headers=user.headers)

        assert response.status_code == 200
        assert response.json() == {
            "ref": ref,
            "state": "CANCELLED",
            "refunded": True,
            "seats_released": 1,
        }

        seat = await _seat(db, flight.id, seat_no)
        assert seat.status == SeatStatus.AVAILABLE
        assert "BOOKING_CANCELLED" in await _audit_events(db, ref)

    async def test_a_cancelled_seat_can_be_sold_again(
        self, client, user, other_user, make_flight, db
    ):
        """Regression: a released seat must be genuinely resellable.

        The first version of this schema had UNIQUE(tickets.seat_inventory_id),
        which reads as "a seat backs one ticket" and is subtly wrong. Cancelling
        returned the seat to inventory but left its ticket pointing at the row,
        so the *next* customer to buy that seat hit a unique violation and a 500
        — the seat was permanently unsellable. Tickets are now voided rather
        than deleted, and the index is partial on `voided_at IS NULL`.
        """
        flight = await make_flight(seats=1)
        seat_no = flight.seat_numbers[0]

        first_hold = await hold_seat(client, user, flight.id, seat_no)
        first_ref = (await book(client, user, [first_hold])).json()["ref"]
        assert (
            await client.post(f"/bookings/{first_ref}/cancel", headers=user.headers)
        ).status_code == 200

        # A different customer buys the released seat.
        second_hold = await hold_seat(client, other_user, flight.id, seat_no)
        second = await book(client, other_user, [second_hold])
        assert second.status_code == 201, second.text
        assert second.json()["ref"] != first_ref
        assert len(second.json()["tickets"]) == 1

        # The original ticket is retained as history, but voided.
        seat = await _seat(db, flight.id, seat_no)
        tickets = list(
            (await db.scalars(select(Ticket).where(Ticket.seat_inventory_id == seat.id))).all()
        )
        assert len(tickets) == 2, "the cancelled ticket is kept, not deleted"
        assert sum(1 for t in tickets if t.voided_at is None) == 1, "exactly one live ticket"

    async def test_a_cancelled_booking_shows_no_boarding_passes(self, client, user, make_flight):
        flight = await make_flight(seats=2)
        hold = await hold_seat(client, user, flight.id, flight.seat_numbers[0])
        ref = (await book(client, user, [hold])).json()["ref"]
        assert (
            len((await client.get(f"/bookings/{ref}", headers=user.headers)).json()["tickets"]) == 1
        )

        await client.post(f"/bookings/{ref}/cancel", headers=user.headers)

        after = await client.get(f"/bookings/{ref}", headers=user.headers)
        assert after.json()["state"] == "CANCELLED"
        assert after.json()["tickets"] == [], "a voided ticket is not a boarding pass"

    async def test_a_compensated_seat_can_be_sold_again(
        self, client, user, other_user, make_flight
    ):
        """Same property on the compensation path, which releases seats too."""
        flight = await make_flight(seats=1)
        seat_no = flight.seat_numbers[0]

        hold = await hold_seat(client, user, flight.id, seat_no)
        assert (
            await book(client, user, [hold], card_token=TICKETING_FAILURE_TOKEN)
        ).status_code == 409

        second_hold = await hold_seat(client, other_user, flight.id, seat_no)
        assert (await book(client, other_user, [second_hold])).status_code == 201

    async def test_cancelling_twice_is_a_409(self, client, user, make_flight):
        flight = await make_flight(seats=4)
        hold = await hold_seat(client, user, flight.id, flight.seat_numbers[0])
        ref = (await book(client, user, [hold])).json()["ref"]

        assert (
            await client.post(f"/bookings/{ref}/cancel", headers=user.headers)
        ).status_code == 200
        second = await client.post(f"/bookings/{ref}/cancel", headers=user.headers)
        assert second.status_code == 409
        assert second.json()["code"] == "invalid_state_transition"


class TestAuditImmutability:
    async def test_the_application_role_cannot_rewrite_history(self, client, user, make_flight, db):
        """Append-only is a database property here, not a convention.

        The app connects as a role with UPDATE and DELETE revoked, and a trigger
        blocks the mutation for every other role too.
        """
        flight = await make_flight(seats=2)
        hold = await hold_seat(client, user, flight.id, flight.seat_numbers[0])
        ref = (await book(client, user, [hold])).json()["ref"]
        booking = await db.scalar(select(Booking).where(Booking.ref == ref))
        booking_id = booking.id

        # Each attempt gets its own session: a failed statement poisons the
        # transaction, and reusing the session would confuse "the write was
        # refused" with "the session was already broken".
        for statement in (
            "UPDATE booking_audit SET event_type = 'FORGED' WHERE booking_id = :b",
            "DELETE FROM booking_audit WHERE booking_id = :b",
            "UPDATE security_events SET severity = 'info'",
            "DELETE FROM security_events",
        ):
            async with SessionLocal() as session:
                with pytest.raises(Exception) as error:
                    await session.execute(text(statement), {"b": booking_id})
                    await session.commit()
                message = str(error.value).lower()
                assert "permission denied" in message or "append-only" in message, (
                    f"{statement!r} was not refused: {message}"
                )

        # And the history is still there, unchanged.
        remaining = await db.scalar(
            select(func.count())
            .select_from(BookingAudit)
            .where(BookingAudit.booking_id == booking_id)
        )
        assert remaining == 5
