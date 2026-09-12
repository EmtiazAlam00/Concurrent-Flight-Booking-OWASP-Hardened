"""Concurrency: the property this service exists to get right.

These are real races. Each coroutine gets its own database session from the
pool and its own connection, so contention happens in Postgres, not in Python.
The assertions are counting assertions ("exactly one winner", "never more than
capacity") because that is the only kind that actually catches an oversell.

A note on why these tests are trustworthy: remove the
`hold_expires_at < now()` guard from `takeable()`, or drop the `.with_for_update()`
in the saga, and they fail. A concurrency test that still passes with the
locking removed is testing nothing.
"""

import asyncio
import uuid

import pytest
from sqlalchemy import func, select

from app.config import settings
from app.domain.enums import BookingState, SeatStatus
from app.domain.models import Booking, SeatInventory, Ticket
from tests.conftest import APPROVE_TOKEN, booking_body

pytestmark = [pytest.mark.concurrency, pytest.mark.integration]


@pytest.fixture
def no_rate_limit():
    """Rate limits would mask the race by rejecting racers before they contend."""
    original = settings.rate_limit_enabled
    settings.rate_limit_enabled = False
    yield
    settings.rate_limit_enabled = original


async def _hold(client, user, flight_id, seat_no):
    return await client.post(
        "/holds",
        headers=user.headers,
        json={"flight_id": str(flight_id), "seat_no": seat_no},
    )


class TestSeatHoldRace:
    async def test_twenty_racers_one_seat_exactly_one_winner(
        self, client, make_user, make_flight, db, no_rate_limit
    ):
        flight = await make_flight(seats=1)
        seat_no = flight.seat_numbers[0]
        users = [await make_user() for _ in range(20)]

        # All twenty requests are in flight before any of them completes.
        responses = await asyncio.gather(*(_hold(client, u, flight.id, seat_no) for u in users))
        codes = sorted(r.status_code for r in responses)

        assert codes.count(201) == 1, f"expected exactly one winner, got {codes}"
        assert codes.count(409) == 19
        assert set(codes) == {201, 409}, "no 500s: losing a race is a normal outcome"

        seat = await db.scalar(
            select(SeatInventory).where(
                SeatInventory.id.in_(
                    select(SeatInventory.id).where(SeatInventory.flight_id == flight.id)
                )
            )
        )
        assert seat.status == SeatStatus.HELD
        assert seat.version == 1, "exactly one write landed on the row"

    async def test_racers_spread_across_a_small_cabin(
        self, client, make_user, make_flight, db, no_rate_limit
    ):
        """Six seats, thirty racers, everyone wants seat 1 or seat 2."""
        flight = await make_flight(seats=6)
        contested = flight.seat_numbers[:2]
        users = [await make_user() for _ in range(30)]

        responses = await asyncio.gather(
            *(
                _hold(client, u, flight.id, contested[index % len(contested)])
                for index, u in enumerate(users)
            )
        )
        assert sum(r.status_code == 201 for r in responses) == 2
        assert all(r.status_code in (201, 409) for r in responses)

        held = await db.scalar(
            select(func.count())
            .select_from(SeatInventory)
            .where(SeatInventory.flight_id == flight.id, SeatInventory.status == "held")
        )
        assert held == 2


class TestBookingRace:
    async def test_full_pipeline_never_oversells(
        self, client, make_user, make_flight, db, no_rate_limit
    ):
        """Hold-then-book, run concurrently, against a four-seat cabin.

        The invariant is not "everyone succeeds" — it is that the number of
        booked seats never exceeds capacity and no seat backs two tickets.
        """
        capacity = 4
        flight = await make_flight(seats=capacity)
        users = [await make_user() for _ in range(16)]

        async def attempt(user, seat_no):
            held = await _hold(client, user, flight.id, seat_no)
            if held.status_code != 201:
                return held.status_code
            hold_id = held.json()["hold_id"]
            booked = await client.post(
                "/bookings",
                headers={**user.headers, "Idempotency-Key": str(uuid.uuid4())},
                json=booking_body([hold_id], APPROVE_TOKEN),
            )
            return booked.status_code

        results = await asyncio.gather(
            *(
                attempt(user, flight.seat_numbers[index % capacity])
                for index, user in enumerate(users)
            )
        )

        confirmed = sum(1 for code in results if code == 201)
        assert confirmed == capacity, f"expected {capacity} bookings, got {confirmed}: {results}"
        assert all(code in (201, 402, 409) for code in results), results

        booked_seats = await db.scalar(
            select(func.count())
            .select_from(SeatInventory)
            .where(
                SeatInventory.flight_id == flight.id,
                SeatInventory.status == SeatStatus.BOOKED,
            )
        )
        assert booked_seats <= capacity
        assert booked_seats == confirmed

        # No seat may back more than one ticket. The unique constraint on
        # tickets.seat_inventory_id makes this structurally impossible, which is
        # exactly why it's worth asserting: it proves the constraint is real.
        seat_ids = [
            row[0]
            for row in (
                await db.execute(
                    select(SeatInventory.id).where(SeatInventory.flight_id == flight.id)
                )
            ).all()
        ]
        ticket_count = await db.scalar(
            select(func.count()).select_from(Ticket).where(Ticket.seat_inventory_id.in_(seat_ids))
        )
        assert ticket_count == confirmed

    async def test_concurrent_multi_seat_bookings_do_not_deadlock(
        self, client, make_user, make_flight, db, no_rate_limit
    ):
        """Two bookings wanting the same pair of seats, requested in opposite order.

        Without deterministic lock ordering this is the textbook deadlock: A
        holds seat 1 and waits for 2 while B holds 2 and waits for 1. The saga
        sorts seats by primary key before locking, so the second transaction
        simply waits its turn.
        """
        flight = await make_flight(seats=2)
        first, second = flight.seat_numbers
        alice, bob = await make_user(), await make_user()

        # Alice takes both seats; Bob can't, so instead we make the *booking*
        # step contend by having each hold one seat and both try to book both.
        alice_hold_1 = (await _hold(client, alice, flight.id, first)).json()["hold_id"]
        bob_hold_2 = (await _hold(client, bob, flight.id, second)).json()["hold_id"]

        async def book_two(user, hold_ids):
            body = booking_body(hold_ids, APPROVE_TOKEN)
            body["passengers"] = [
                {"given_name": "Ada", "family_name": "Lovelace"},
                {"given_name": "Grace", "family_name": "Hopper"},
            ]
            return await client.post(
                "/bookings",
                headers={**user.headers, "Idempotency-Key": str(uuid.uuid4())},
                json=body,
            )

        # Each names the two holds in the opposite order.
        results = await asyncio.gather(
            book_two(alice, [alice_hold_1, bob_hold_2]),
            book_two(bob, [bob_hold_2, alice_hold_1]),
            return_exceptions=True,
        )

        for result in results:
            assert not isinstance(result, Exception), f"deadlock or crash: {result!r}"
            # Neither can succeed — each owns only one of the two holds — but
            # the failure must be a clean 404, never a deadlock error.
            assert result.status_code == 404, result.text

        assert (
            await db.scalar(
                select(func.count())
                .select_from(Booking)
                .where(Booking.state == BookingState.CONFIRMED)
                .where(Booking.flight_id == flight.id)
            )
            == 0
        )


class TestSweepRaces:
    async def test_sweep_cannot_steal_a_seat_mid_checkout(
        self, client, user, make_flight, db, no_rate_limit
    ):
        """The sweep runs against a seat that is being booked right now.

        The sweep's UPDATE is conditional on the seat still being expired-and-
        held *and* unattached to a booking, so it can never pull a seat out from
        under an in-flight saga.
        """
        from app.jobs.sweep import sweep_expired_holds

        flight = await make_flight(seats=2)
        seat_no = flight.seat_numbers[0]
        hold_id = (await _hold(client, user, flight.id, seat_no)).json()["hold_id"]

        booking_task = asyncio.create_task(
            client.post(
                "/bookings",
                headers={**user.headers, "Idempotency-Key": str(uuid.uuid4())},
                json=booking_body([hold_id], APPROVE_TOKEN),
            )
        )
        sweep_task = asyncio.create_task(sweep_expired_holds())
        booked, released = await asyncio.gather(booking_task, sweep_task)

        assert booked.status_code == 201, booked.text
        assert released == 0

        seat = await db.scalar(
            select(SeatInventory).where(
                SeatInventory.flight_id == flight.id, SeatInventory.seat_no == seat_no
            )
        )
        assert seat.status == SeatStatus.BOOKED

    async def test_sweep_releases_only_genuinely_expired_holds(self, client, user, make_flight, db):
        from datetime import UTC, datetime, timedelta

        from sqlalchemy import update

        from app.jobs.sweep import sweep_expired_holds

        flight = await make_flight(seats=3)
        live = flight.seat_numbers[0]
        stale = flight.seat_numbers[1]
        for seat_no in (live, stale):
            await _hold(client, user, flight.id, seat_no)

        await db.execute(
            update(SeatInventory)
            .where(SeatInventory.flight_id == flight.id, SeatInventory.seat_no == stale)
            .values(hold_expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        await db.commit()

        released = await sweep_expired_holds()
        assert released == 1

        rows = {
            seat.seat_no: seat.status
            for seat in (
                await db.scalars(select(SeatInventory).where(SeatInventory.flight_id == flight.id))
            ).all()
        }
        assert rows[live] == SeatStatus.HELD
        assert rows[stale] == SeatStatus.AVAILABLE


class TestLazyExpiryIndependentOfSweep:
    async def test_an_expired_hold_frees_the_seat_before_the_sweep_runs(
        self, client, user, other_user, make_flight, db
    ):
        """The property that makes the sweep optional.

        The sweep is never called in this test. An expired hold must already be
        takeable, because availability is decided by the WHERE clause, not by a
        background job having got around to it.
        """
        from datetime import UTC, datetime, timedelta

        from sqlalchemy import update

        flight = await make_flight(seats=1)
        seat_no = flight.seat_numbers[0]

        assert (await _hold(client, user, flight.id, seat_no)).status_code == 201
        assert (await _hold(client, other_user, flight.id, seat_no)).status_code == 409

        await db.execute(
            update(SeatInventory)
            .where(SeatInventory.flight_id == flight.id, SeatInventory.seat_no == seat_no)
            .values(hold_expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        await db.commit()

        # The row still literally says status='held'. It is nonetheless free.
        stale = await db.scalar(
            select(SeatInventory).where(
                SeatInventory.flight_id == flight.id, SeatInventory.seat_no == seat_no
            )
        )
        assert stale.status == SeatStatus.HELD

        response = await _hold(client, other_user, flight.id, seat_no)
        assert response.status_code == 201, "expired hold must not block a new one"

        seat_map = await client.get(f"/flights/{flight.id}/seats")
        assert seat_map.json()["available_seats"] == 0  # now genuinely held again
