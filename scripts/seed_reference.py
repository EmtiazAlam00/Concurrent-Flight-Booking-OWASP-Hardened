"""Load real airports, airlines and routes into Postgres.

Why real reference data: route data tells you which airlines actually fly which
city pairs, so the generated flights are plausible rather than toy. It also
means ordinary SQL questions ("which airlines depart YOW?") have real answers
from the moment the database is seeded.

Sources, both openly licensed:
  * OurAirports  — worldwide airports, public domain, updated daily
  * OpenFlights  — airlines and routes, Open Database License (fine for a
                   non-commercial portfolio; commercial use needs a licence)

Downloads are cached under data/ and the load is idempotent (ON CONFLICT DO
NOTHING), so re-running is cheap and safe.

    python -m scripts.seed_reference [--refresh]
"""

import argparse
import asyncio
import csv
import io
import logging
from pathlib import Path

import httpx
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.db import session_scope
from app.domain.models import Airline, Airport, Route

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("seed.reference")

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

SOURCES = {
    "airports.csv": "https://davidmegginson.github.io/ourairports-data/airports.csv",
    "airlines.dat": (
        "https://raw.githubusercontent.com/jpatokal/openflights/master/data/airlines.dat"
    ),
    "routes.dat": ("https://raw.githubusercontent.com/jpatokal/openflights/master/data/routes.dat"),
}

#: Only airports that actually see scheduled service. Dropping the other ~75k
#: rows keeps joins fast and stops the flight generator inventing service to
#: private airstrips.
USEFUL_AIRPORT_TYPES = {"large_airport", "medium_airport"}

BATCH = 2_000


async def fetch(name: str, *, refresh: bool = False) -> str:
    path = DATA_DIR / name
    if path.exists() and not refresh:
        logger.info("  using cached %s (%.1f MB)", name, path.stat().st_size / 1e6)
        return path.read_text(encoding="utf-8", errors="replace")

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("  downloading %s", name)
    async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
        response = await client.get(SOURCES[name])
        response.raise_for_status()
    text = response.text
    path.write_text(text, encoding="utf-8")
    logger.info("  saved %s (%.1f MB)", name, len(text.encode()) / 1e6)
    return text


def parse_airports(raw: str) -> list[dict]:
    rows = []
    for row in csv.DictReader(io.StringIO(raw)):
        iata = (row.get("iata_code") or "").strip().upper()
        if len(iata) != 3 or not iata.isalpha():
            continue
        if row.get("type") not in USEFUL_AIRPORT_TYPES:
            continue
        if (row.get("scheduled_service") or "").strip() != "yes":
            continue
        try:
            lat = float(row["latitude_deg"])
            lon = float(row["longitude_deg"])
        except (KeyError, TypeError, ValueError):
            lat = lon = None
        rows.append(
            {
                "iata": iata,
                "icao": (row.get("gps_code") or "").strip().upper()[:4] or None,
                "name": (row.get("name") or iata)[:200],
                "city": (row.get("municipality") or "").strip()[:120] or None,
                "country": (row.get("iso_country") or "").strip().upper()[:2] or None,
                "latitude": lat,
                "longitude": lon,
                "timezone": None,  # OurAirports' CSV does not carry tz; not needed
            }
        )
    # One row per IATA code: a handful of codes appear twice in the source.
    return list({r["iata"]: r for r in rows}.values())


def parse_airlines(raw: str) -> list[dict]:
    rows = []
    for record in csv.reader(io.StringIO(raw)):
        # Airline ID, Name, Alias, IATA, ICAO, Callsign, Country, Active
        if len(record) < 8:
            continue
        iata = record[3].strip().upper()
        if len(iata) != 2 or iata in {"-", r"\N"} or not iata.isalnum():
            continue
        if record[7].strip() != "Y":
            continue
        rows.append(
            {
                "iata": iata,
                "icao": (record[4].strip().upper()[:3] or None)
                if record[4].strip() not in {r"\N", "-", ""}
                else None,
                "name": record[1].strip()[:200] or iata,
                "country": record[6].strip()[:80] or None,
                "active": True,
            }
        )
    return list({r["iata"]: r for r in rows}.values())


def parse_routes(raw: str, airports: set[str], airlines: set[str]) -> list[dict]:
    seen: set[tuple[str, str, str]] = set()
    rows = []
    for record in csv.reader(io.StringIO(raw)):
        # Airline, Airline ID, Source, Source ID, Dest, Dest ID, Codeshare, Stops, Equipment
        if len(record) < 9:
            continue
        airline, src, dst, stops, equipment = (
            record[0].strip().upper(),
            record[2].strip().upper(),
            record[4].strip().upper(),
            record[7].strip(),
            record[8].strip(),
        )
        if airline not in airlines or src not in airports or dst not in airports:
            continue
        if src == dst or stops not in {"0", ""}:
            continue
        key = (airline, src, dst)
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "airline_iata": airline,
                "src_iata": src,
                "dst_iata": dst,
                "equipment": equipment[:120] or None,
            }
        )
    return rows


async def bulk_upsert(model, rows: list[dict], conflict_cols: list[str], label: str) -> None:
    if not rows:
        logger.warning("  no %s rows to load", label)
        return
    async with session_scope() as session:
        for start in range(0, len(rows), BATCH):
            chunk = rows[start : start + BATCH]
            await session.execute(
                pg_insert(model).values(chunk).on_conflict_do_nothing(index_elements=conflict_cols)
            )
    logger.info("  loaded %s %s", f"{len(rows):,}", label)


async def main(refresh: bool = False) -> None:
    logger.info("Reference data")

    airports_raw = await fetch("airports.csv", refresh=refresh)
    airlines_raw = await fetch("airlines.dat", refresh=refresh)
    routes_raw = await fetch("routes.dat", refresh=refresh)

    airports = parse_airports(airports_raw)
    airlines = parse_airlines(airlines_raw)
    routes = parse_routes(
        routes_raw,
        {a["iata"] for a in airports},
        {a["iata"] for a in airlines},
    )

    await bulk_upsert(Airport, airports, ["iata"], "airports")
    await bulk_upsert(Airline, airlines, ["iata"], "airlines")
    await bulk_upsert(Route, routes, ["airline_iata", "src_iata", "dst_iata"], "routes")

    async with session_scope() as session:
        counts = {
            "airports": await session.scalar(select(func.count()).select_from(Airport)),
            "airlines": await session.scalar(select(func.count()).select_from(Airline)),
            "routes": await session.scalar(select(func.count()).select_from(Route)),
        }
        sample = (
            await session.execute(
                select(Airline.name, func.count(Route.id))
                .join(Route, Route.airline_iata == Airline.iata)
                .where(Route.src_iata == "YOW")
                .group_by(Airline.name)
                .order_by(func.count(Route.id).desc())
                .limit(5)
            )
        ).all()

    logger.info("In database: %s", ", ".join(f"{v:,} {k}" for k, v in counts.items()))
    if sample:
        logger.info("Sanity check — airlines departing YOW (Ottawa):")
        for name, count in sample:
            logger.info("  %-42s %2d routes", name, count)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--refresh", action="store_true", help="re-download even if cached in data/"
    )
    args = parser.parse_args()
    asyncio.run(main(refresh=args.refresh))
