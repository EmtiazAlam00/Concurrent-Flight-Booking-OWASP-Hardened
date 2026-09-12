"""Generate bookable flights and seat inventory on top of the real routes.

No free API provides bookable seat inventory — that data is proprietary to
airlines and GDSs. So this script *generates* flight instances on real routes
flown by real airlines, each with a seat map priced from the actual
great-circle distance between the two airports.

Keeping this self-generated is deliberate: the concurrency, hold and security
logic — the part that matters — never depends on anyone's rate-limited free
tier.

Inserts are batched through SQLAlchemy's executemany path rather than looping
ORM objects, because the seat table is where the row count lives: a full-scale
run is several hundred thousand rows and the naive version takes minutes.

    python -m scripts.seed_flights --scale demo --days 7
"""

import argparse
import asyncio
import logging
import math
import random
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from sqlalchemy import delete, func, insert, select

from app.db import session_scope
from app.domain.models import Airport, FareClass, Flight, Route, SeatInventory
from app.domain.money import money

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("seed.flights")

SEAT_BATCH = 5_000


# ---------------------------------------------------------------------------
# seat maps
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CabinBlock:
    cabin: str
    code: str  # fare class code: J business, W premium, Y economy
    multiplier: Decimal
    first_row: int
    last_row: int
    letters: str
    exit_rows: tuple[int, ...] = ()

    @property
    def seat_count(self) -> int:
        return (self.last_row - self.first_row + 1) * len(self.letters)


#: Four aircraft, four genuinely different layouts — so the seat-map endpoint
#: returns something recognisable rather than a generic grid.
AIRCRAFT: dict[str, list[CabinBlock]] = {
    "CRJ9": [
        CabinBlock("economy", "Y", Decimal("1.0"), 1, 19, "ABCD", exit_rows=(10,)),
    ],
    "A320": [
        CabinBlock("business", "J", Decimal("2.8"), 1, 3, "ACDF"),
        CabinBlock("economy", "Y", Decimal("1.0"), 10, 32, "ABCDEF", exit_rows=(14, 15)),
    ],
    "B738": [
        CabinBlock("business", "J", Decimal("2.8"), 1, 4, "ACDF"),
        CabinBlock("economy", "Y", Decimal("1.0"), 10, 33, "ABCDEF", exit_rows=(16, 17)),
    ],
    "B77W": [
        CabinBlock("business", "J", Decimal("3.4"), 1, 7, "ACDFGJ"),
        CabinBlock("premium", "W", Decimal("1.7"), 20, 24, "ACDEFGHJ"),
        CabinBlock("economy", "Y", Decimal("1.0"), 30, 57, "ABCDEFGHJK", exit_rows=(40, 41)),
    ],
}

EXIT_ROW_SURCHARGE = Decimal("28.00")


#: Short-haul gets narrowbodies, long-haul gets the 777. Chosen by distance so
#: nothing absurd appears (no CRJ on a transatlantic).
def aircraft_for(distance_km: float) -> str:
    if distance_km < 700:
        return random.choice(["CRJ9", "A320"])
    if distance_km < 2_500:
        return random.choice(["A320", "B738"])
    if distance_km < 6_000:
        return random.choice(["B738", "B77W"])
    return "B77W"


# ---------------------------------------------------------------------------
# geometry and pricing
# ---------------------------------------------------------------------------


def great_circle_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = p2 - p1
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def block_minutes(distance_km: float) -> int:
    """Rough block time: 850 km/h cruise plus 35 minutes of taxi and climb."""
    return int(round(distance_km / 850 * 60)) + 35


def base_fare_for(distance_km: float) -> Decimal:
    """A plausible economy base fare. Not a revenue-management model."""
    fare = Decimal("68") + Decimal(str(round(distance_km * 0.085, 2)))
    return money(fare)


# ---------------------------------------------------------------------------
# scale presets
# ---------------------------------------------------------------------------

#: Demo scale is pinned to these airports so a demo always has something to
#: search for, and `make seed` finishes in seconds rather than minutes.
DEMO_HUBS = ["YOW", "YYZ", "YUL", "YVR", "JFK", "LHR", "ORD", "SFO"]

SCALES = {
    "demo": {"routes": 24, "flights_per_route_per_day": 1, "hubs": DEMO_HUBS},
    "small": {"routes": 150, "flights_per_route_per_day": 1, "hubs": None},
    "full": {"routes": 600, "flights_per_route_per_day": 2, "hubs": None},
}

DEPARTURE_SLOTS = [(7, 5), (9, 40), (12, 15), (14, 50), (17, 30), (20, 10)]


async def pick_routes(session, count: int, hubs: list[str] | None) -> list[Route]:
    """Choose routes that both airports have coordinates for.

    Coordinates are required because the duration and the fare are derived from
    the real distance; a route missing them would produce nonsense.
    """
    src = Airport.__table__.alias("src")
    dst = Airport.__table__.alias("dst")
    stmt = (
        select(Route)
        .join(src, src.c.iata == Route.src_iata)
        .join(dst, dst.c.iata == Route.dst_iata)
        .where(
            src.c.latitude.is_not(None),
            dst.c.latitude.is_not(None),
        )
    )
    if hubs:
        stmt = stmt.where(Route.src_iata.in_(hubs), Route.dst_iata.in_(hubs))
    # Deterministic but *shuffled*: ordering by the natural key would return
    # routes grouped by airline (the source file is sorted that way), so a demo
    # world would end up as one carrier's network. Hashing the key mixes
    # carriers while keeping repeated seeds identical.
    shuffle_key = func.md5(Route.airline_iata + Route.src_iata + Route.dst_iata)
    stmt = stmt.order_by(shuffle_key).limit(count)
    routes = list((await session.scalars(stmt)).all())

    if hubs and len(routes) < count:
        # Hub-only filtering can come up short; top up from anywhere.
        logger.info("  hub filter yielded %d routes; topping up", len(routes))
        extra = (
            select(Route)
            .join(src, src.c.iata == Route.src_iata)
            .join(dst, dst.c.iata == Route.dst_iata)
            .where(src.c.latitude.is_not(None), dst.c.latitude.is_not(None))
            .where(Route.id.not_in([r.id for r in routes]) if routes else True)
            .order_by(Route.id)
            .limit(count - len(routes))
        )
        routes += list((await session.scalars(extra)).all())
    return routes


async def main(scale: str, days: int, start_offset: int, wipe: bool, seed: int) -> None:
    random.seed(seed)
    preset = SCALES[scale]

    async with session_scope() as session:
        reference_rows = await session.scalar(select(func.count()).select_from(Route))
        if not reference_rows:
            raise SystemExit(
                "No routes in the database. Run `python -m scripts.seed_reference` first."
            )

        if wipe:
            logger.info("Removing previously generated flights")
            # Seats and fare classes cascade from flights.
            await session.execute(delete(Flight))

        routes = await pick_routes(session, preset["routes"], preset["hubs"])
        logger.info("Generating %s scale: %d routes x %d day(s)", scale, len(routes), days)

        needed = {r.src_iata for r in routes} | {r.dst_iata for r in routes}
        coords = {
            iata: (lat, lon)
            for iata, lat, lon in (
                await session.execute(
                    select(Airport.iata, Airport.latitude, Airport.longitude).where(
                        Airport.iata.in_(needed)
                    )
                )
            ).all()
        }

        flight_rows: list[dict] = []
        fare_rows: list[dict] = []
        seat_rows: list[dict] = []
        flight_no_counter: dict[str, int] = {}

        day0 = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(
            days=start_offset
        )

        for route in routes:
            (lat1, lon1) = coords[route.src_iata]
            (lat2, lon2) = coords[route.dst_iata]
            distance = great_circle_km(lat1, lon1, lat2, lon2)
            duration = timedelta(minutes=block_minutes(distance))
            base_fare = base_fare_for(distance)
            aircraft = aircraft_for(distance)

            n = flight_no_counter.get(route.airline_iata, 100)
            flight_no_counter[route.airline_iata] = n + 1
            flight_no = f"{route.airline_iata}{n}"

            slots = random.sample(
                DEPARTURE_SLOTS, k=min(preset["flights_per_route_per_day"], len(DEPARTURE_SLOTS))
            )

            for day in range(days):
                for hour, minute in slots:
                    depart = day0 + timedelta(days=day, hours=hour, minutes=minute)
                    flight_id = uuid.uuid4()
                    flight_rows.append(
                        {
                            "id": flight_id,
                            "flight_no": flight_no,
                            "airline_iata": route.airline_iata,
                            "src_iata": route.src_iata,
                            "dst_iata": route.dst_iata,
                            "depart_at": depart,
                            "arrive_at": depart + duration,
                            "aircraft_type": aircraft,
                            "base_fare": base_fare,
                            "currency": "CAD",
                        }
                    )

                    for block in AIRCRAFT[aircraft]:
                        fare_class_id = uuid.uuid4()
                        fare_rows.append(
                            {
                                "id": fare_class_id,
                                "flight_id": flight_id,
                                "code": block.code,
                                "cabin": block.cabin,
                                "multiplier": block.multiplier,
                                "seats_total": block.seat_count,
                            }
                        )
                        cabin_price = money(base_fare * block.multiplier)
                        for row_no in range(block.first_row, block.last_row + 1):
                            is_exit = row_no in block.exit_rows
                            price = (
                                money(cabin_price + EXIT_ROW_SURCHARGE) if is_exit else cabin_price
                            )
                            for letter in block.letters:
                                seat_rows.append(
                                    {
                                        "id": uuid.uuid4(),
                                        "flight_id": flight_id,
                                        "seat_no": f"{row_no}{letter}",
                                        "row_no": row_no,
                                        "seat_letter": letter,
                                        "cabin": block.cabin,
                                        "fare_class_id": fare_class_id,
                                        "is_exit_row": is_exit,
                                        "price": price,
                                        "status": "available",
                                        "version": 0,
                                    }
                                )

        logger.info(
            "  inserting %s flights, %s fare classes, %s seats",
            f"{len(flight_rows):,}",
            f"{len(fare_rows):,}",
            f"{len(seat_rows):,}",
        )
        for start in range(0, len(flight_rows), SEAT_BATCH):
            await session.execute(insert(Flight), flight_rows[start : start + SEAT_BATCH])
        for start in range(0, len(fare_rows), SEAT_BATCH):
            await session.execute(insert(FareClass), fare_rows[start : start + SEAT_BATCH])
        for start in range(0, len(seat_rows), SEAT_BATCH):
            await session.execute(insert(SeatInventory), seat_rows[start : start + SEAT_BATCH])

    async with session_scope() as session:
        sample = (
            await session.execute(
                select(
                    Flight.flight_no,
                    Flight.src_iata,
                    Flight.dst_iata,
                    Flight.depart_at,
                    Flight.aircraft_type,
                    Flight.base_fare,
                    func.count(SeatInventory.id),
                )
                .join(SeatInventory, SeatInventory.flight_id == Flight.id)
                .group_by(Flight.id)
                .order_by(Flight.depart_at)
                .limit(5)
            )
        ).all()

    logger.info("Done. Try these:")
    for no, src, dst, depart, aircraft, fare, seats in sample:
        logger.info(
            "  GET /flights/search?origin=%s&destination=%s&departure_date=%s"
            "   (%s %s, %d seats, from %s CAD)",
            src,
            dst,
            depart.date().isoformat(),
            no,
            aircraft,
            seats,
            fare,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scale", choices=sorted(SCALES), default="demo")
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument(
        "--start-offset", type=int, default=1, help="first departure day, relative to today"
    )
    parser.add_argument(
        "--wipe", action="store_true", help="delete existing generated flights first"
    )
    parser.add_argument("--seed", type=int, default=20260909, help="RNG seed")
    args = parser.parse_args()
    asyncio.run(main(args.scale, args.days, args.start_offset, args.wipe, args.seed))
