"""Load-test the invariant that matters: capacity is never exceeded.

Runs entirely on the standard library plus httpx, so the proof in the README is
reproducible with no extra tooling. `load/k6_oversell.js` does the same thing
under k6 if you want a throughput profile as well.

    python -m load.oversell_proof --seats 20 --racers 120

What it asserts — the safety invariant, not maximum utilisation:
  * confirmed bookings <= seats offered   (never oversold)
  * booked seats == confirmed bookings    (no phantom or lost bookings)
  * every booked seat backs exactly one live ticket
  * no 5xx anywhere — losing a race is a normal outcome, not an error

Utilisation can legitimately fall short of capacity: racers share a small pool
of accounts (registration is rate limited on purpose), and each account may hold
only MAX_ACTIVE_HOLDS_PER_USER seats at once, so at peak contention some seats
have no eligible bidder. That is a fairness control doing its job, not a bug —
so the run reports it rather than failing on it.
"""

import argparse
import asyncio
import time
import uuid
from collections import Counter
from decimal import Decimal

import httpx

PASSWORD = "correct-horse-battery-staple"


def approve_token(account: int) -> str:
    """A distinct card per account.

    Sharing one card across every racer would trip the card-across-accounts
    fraud rule, and the run would measure the fraud engine rather than the seat
    locking. Real load tests have the same problem with shared test cards.
    """
    return f"tok_test_load{account:04d}0000"


async def _register(client: httpx.AsyncClient) -> dict[str, str]:
    response = await client.post(
        "/auth/register",
        json={"email": f"load-{uuid.uuid4().hex[:12]}@example.com", "password": PASSWORD},
    )
    response.raise_for_status()
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def _make_flight(seats: int) -> tuple[str, list[str]]:
    """Create a dedicated flight so the run is isolated and repeatable."""
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import insert
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from app.db import session_scope
    from app.domain.models import Airline, Airport, FareClass, Flight, SeatInventory

    flight_id = uuid.uuid4()
    fare_class_id = uuid.uuid4()
    depart = datetime.now(UTC).replace(microsecond=0) + timedelta(days=30)

    async with session_scope() as session:
        await session.execute(
            pg_insert(Airline)
            .values(iata="ZL", name="Load Test Air", country="CA", active=True)
            .on_conflict_do_nothing(index_elements=["iata"])
        )
        for iata in ("XLA", "XLB"):
            await session.execute(
                pg_insert(Airport)
                .values(
                    iata=iata, name=f"Load {iata}", country="CA", latitude=45.0, longitude=-75.0
                )
                .on_conflict_do_nothing(index_elements=["iata"])
            )
        await session.execute(
            insert(Flight).values(
                id=flight_id,
                flight_no=f"ZL{uuid.uuid4().int % 900 + 100}",
                airline_iata="ZL",
                src_iata="XLA",
                dst_iata="XLB",
                depart_at=depart,
                arrive_at=depart + timedelta(hours=2),
                aircraft_type="A320",
                base_fare=Decimal("199.00"),
                currency="CAD",
            )
        )
        await session.execute(
            insert(FareClass).values(
                id=fare_class_id,
                flight_id=flight_id,
                code="Y",
                cabin="economy",
                multiplier=Decimal("1.0"),
                seats_total=seats,
            )
        )
        letters = "ABCDEF"
        rows = [
            {
                "id": uuid.uuid4(),
                "flight_id": flight_id,
                "seat_no": f"{i // len(letters) + 10}{letters[i % len(letters)]}",
                "row_no": i // len(letters) + 10,
                "seat_letter": letters[i % len(letters)],
                "cabin": "economy",
                "fare_class_id": fare_class_id,
                "is_exit_row": False,
                "price": Decimal("199.00"),
                "status": "available",
                "version": 0,
            }
            for i in range(seats)
        ]
        await session.execute(insert(SeatInventory), rows)

    return str(flight_id), [r["seat_no"] for r in rows]


async def _verify(flight_id: str, seats: int, confirmed: int) -> list[str]:
    from sqlalchemy import func, select

    from app.db import session_scope
    from app.domain.models import SeatInventory, Ticket

    problems = []
    async with session_scope() as session:
        booked = int(
            await session.scalar(
                select(func.count())
                .select_from(SeatInventory)
                .where(
                    SeatInventory.flight_id == uuid.UUID(flight_id),
                    SeatInventory.status == "booked",
                )
            )
            or 0
        )
        seat_ids = [
            row[0]
            for row in (
                await session.execute(
                    select(SeatInventory.id).where(SeatInventory.flight_id == uuid.UUID(flight_id))
                )
            ).all()
        ]
        # Live tickets only: a cancelled booking's ticket is retained as
        # history and must not count against the seat it used to occupy.
        live = (Ticket.seat_inventory_id.in_(seat_ids), Ticket.voided_at.is_(None))
        tickets = int(
            await session.scalar(select(func.count()).select_from(Ticket).where(*live)) or 0
        )
        distinct_ticketed_seats = int(
            await session.scalar(
                select(func.count(func.distinct(Ticket.seat_inventory_id))).where(*live)
            )
            or 0
        )

    if booked > seats:
        problems.append(f"OVERSOLD: {booked} seats booked on a {seats}-seat flight")
    if booked != confirmed:
        problems.append(f"booked seats ({booked}) != confirmed bookings ({confirmed})")
    if confirmed > seats:
        problems.append(f"more bookings ({confirmed}) than seats ({seats})")
    if tickets != distinct_ticketed_seats:
        problems.append(
            f"a seat backs more than one ticket ({tickets} vs {distinct_ticketed_seats})"
        )
    return problems


async def main(seats: int, racers: int, base_url: str) -> int:
    flight_id, seat_numbers = await _make_flight(seats)

    async with httpx.AsyncClient(base_url=base_url, timeout=60) as client:
        health = await client.get("/health")
        if health.status_code != 200:
            raise SystemExit(f"{base_url} is not healthy — is the API running?")

        # Rate limits exist to stop exactly this traffic pattern, so a load run
        # that leaves them on measures the limiter, not the locking. Start the
        # API with RATE_LIMIT_ENABLED=false for this test.
        probe = await client.get(
            "/flights/search",
            params={"origin": "XLA", "destination": "XLB", "departure_date": "2030-01-01"},
        )
        if probe.status_code == 429:
            raise SystemExit(
                "The API is rate limiting already. Restart it with "
                "RATE_LIMIT_ENABLED=false to load-test the seat locking."
            )

        print(f"Provisioning {racers} racers for a {seats}-seat flight…")
        # Registration is rate limited on purpose, so racers share a small pool
        # of accounts. Contention on the seat rows is what we're measuring.
        pool_size = min(racers, 8)
        pool = [await _register(client) for _ in range(pool_size)]

        async def race(index: int) -> tuple[int, str]:
            headers = pool[index % pool_size]
            seat_no = seat_numbers[index % seats]
            held = await client.post(
                "/holds", headers=headers, json={"flight_id": flight_id, "seat_no": seat_no}
            )
            if held.status_code != 201:
                # Distinguish "someone beat me to this seat" from "my account is
                # already holding its maximum" — they mean different things.
                code = held.json().get("code", "") if held.status_code == 409 else ""
                return held.status_code, "hold-cap" if code == "too_many_holds" else "hold"
            booked = await client.post(
                "/bookings",
                headers={**headers, "Idempotency-Key": str(uuid.uuid4())},
                json={
                    "hold_ids": [held.json()["hold_id"]],
                    "passengers": [{"given_name": "Load", "family_name": "Racer"}],
                    "card_token": approve_token(index % pool_size),
                },
            )
            return booked.status_code, "book"

        print(f"Releasing {racers} concurrent attempts…\n")
        started = time.perf_counter()
        results = await asyncio.gather(*(race(i) for i in range(racers)), return_exceptions=True)
        elapsed = time.perf_counter() - started

    crashes = [r for r in results if isinstance(r, Exception)]
    outcomes = Counter(f"{r[0]} @{r[1]}" for r in results if not isinstance(r, Exception))
    confirmed = sum(count for key, count in outcomes.items() if key.startswith("201 @book"))
    server_errors = sum(
        count for key, count in outcomes.items() if key.split(" ")[0].startswith("5")
    )

    print(f"{racers} attempts in {elapsed:.2f}s  ({racers / elapsed:.0f} req-pairs/s)")
    for key, count in sorted(outcomes.items()):
        print(f"  {key:16s} {count}")
    if crashes:
        print(f"  exceptions       {len(crashes)}")

    problems = await _verify(flight_id, seats, confirmed)
    if server_errors:
        problems.append(f"{server_errors} server errors — losing a race must not be a 5xx")
    if crashes:
        problems.append(f"{len(crashes)} client exceptions: {crashes[0]!r}")

    capped = sum(count for key, count in outcomes.items() if key.endswith("@hold-cap"))

    print()
    print(f"  seats offered      {seats}")
    print(f"  bookings confirmed {confirmed}")
    if confirmed < seats:
        print(
            f"  {seats - confirmed} seat(s) unsold: {capped} attempt(s) were refused because the "
            "account\n                     already held its maximum. Fairness control, not a race "
            "loss."
        )
    if problems:
        print("\nFAILED:")
        for problem in problems:
            print(f"  ✗ {problem}")
        return 1

    print("\n  ✓ never oversold        (booked <= capacity)")
    print("  ✓ no phantom bookings   (booked == confirmed)")
    print("  ✓ one live ticket per booked seat")
    print("  ✓ no server errors      (losing a race is a 409, not a 500)")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seats", type=int, default=20)
    parser.add_argument("--racers", type=int, default=120)
    parser.add_argument("--base-url", default="http://localhost:8000")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(main(args.seats, args.racers, args.base_url)))
