"""Test fixtures.

Integration tests run against a **real** Postgres and Redis. Nothing about the
locking behaviour this service exists to get right survives being mocked, so
mocking the database would test the mock.
"""

import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal

# Point tests at a separate Redis database *before* app config is imported, so a
# test run never stomps on the rate-limit and velocity windows of a dev session.
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")

import pytest  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy import delete, insert, select  # noqa: E402
from sqlalchemy.dialects.postgresql import insert as pg_insert  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: E402

from app.config import settings  # noqa: E402
from app.db import SessionLocal  # noqa: E402
from app.domain.models import (  # noqa: E402
    Airline,
    Airport,
    FareClass,
    Flight,
    SeatInventory,
    User,
)
from app.main import app  # noqa: E402
from app.redis_client import get_redis  # noqa: E402
from app.services.payments import get_gateway  # noqa: E402

TEST_AIRLINE = "ZZ"
TEST_ORIGIN = "XAA"
TEST_DEST = "XBB"

APPROVE_TOKEN = "tok_test_aaaa11110000"
DECLINE_TOKEN = "tok_test_aaaa11110002"
TICKETING_FAILURE_TOKEN = "tok_test_aaaa11119995"
TIMEOUT_TOKEN = "tok_test_aaaa11110119"
REFUND_FAILURE_TOKEN = "tok_test_aaaa11115309"

STRONG_PASSWORD = "correct-horse-battery-staple"


@pytest.fixture(autouse=True)
async def _isolate_state(request) -> AsyncIterator[None]:
    """Clear Redis windows and the fake gateway's memory between tests.

    Without this, one test's rate-limit bucket or velocity counter leaks into
    the next and failures become order-dependent.

    Skipped for tests/unit so that suite stays runnable with no datastores.
    """
    if "/tests/unit/" in str(request.node.fspath).replace("\\", "/"):
        yield
        return

    await get_redis().flushdb()
    gateway = get_gateway()
    if hasattr(gateway, "reset"):
        gateway.reset()
    yield
    await get_redis().flushdb()


@pytest.fixture
async def db() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        yield session


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# ---------------------------------------------------------------------------
# users
# ---------------------------------------------------------------------------


class TestUser:
    def __init__(self, email: str, user_id: uuid.UUID, access: str, refresh: str):
        self.email = email
        self.id = user_id
        self.access = access
        self.refresh = refresh

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access}"}


@pytest.fixture
async def make_user(client: AsyncClient, db: AsyncSession):
    async def _make(*, admin: bool = False, password: str = STRONG_PASSWORD) -> TestUser:
        email = f"t-{uuid.uuid4().hex[:12]}@example.com"
        response = await client.post("/auth/register", json={"email": email, "password": password})
        assert response.status_code == 201, response.text
        body = response.json()

        row = await db.scalar(select(User).where(User.email == email))
        assert row is not None
        if admin:
            row.is_admin = True
            await db.commit()
            # Re-login so the new access token carries the admin scope.
            response = await client.post("/auth/login", json={"email": email, "password": password})
            body = response.json()

        return TestUser(email, row.id, body["access_token"], body["refresh_token"])

    return _make


@pytest.fixture
async def user(make_user) -> TestUser:
    return await make_user()


@pytest.fixture
async def other_user(make_user) -> TestUser:
    return await make_user()


@pytest.fixture
async def admin(make_user) -> TestUser:
    return await make_user(admin=True)


# ---------------------------------------------------------------------------
# inventory
# ---------------------------------------------------------------------------


class TestFlight:
    def __init__(self, flight_id: uuid.UUID, seat_numbers: list[str], price: Decimal):
        self.id = flight_id
        self.seat_numbers = seat_numbers
        self.price = price


@pytest.fixture
async def make_flight(db: AsyncSession):
    """Create a flight with a deliberately tiny cabin.

    Small cabins make contention tests meaningful: with four seats and twenty
    racers, "exactly four winners" is a sharp assertion.
    """
    created: list[uuid.UUID] = []

    await db.execute(
        pg_insert(Airline)
        .values(iata=TEST_AIRLINE, name="Test Air", country="CA", active=True)
        .on_conflict_do_nothing(index_elements=["iata"])
    )
    for iata, name in ((TEST_ORIGIN, "Test Origin"), (TEST_DEST, "Test Destination")):
        await db.execute(
            pg_insert(Airport)
            .values(iata=iata, name=name, city=name, country="CA", latitude=45.0, longitude=-75.0)
            .on_conflict_do_nothing(index_elements=["iata"])
        )
    await db.commit()

    async def _make(
        *,
        seats: int = 6,
        price: Decimal = Decimal("250.00"),
        depart_in_days: int = 3,
    ) -> TestFlight:
        flight_id = uuid.uuid4()
        fare_class_id = uuid.uuid4()
        depart = datetime.now(UTC).replace(microsecond=0) + timedelta(days=depart_in_days)
        await db.execute(
            insert(Flight).values(
                id=flight_id,
                # Unique per flight so the (airline, flight_no, depart_at)
                # constraint never collides across tests.
                flight_no=f"ZZ{uuid.uuid4().int % 900 + 100}",
                airline_iata=TEST_AIRLINE,
                src_iata=TEST_ORIGIN,
                dst_iata=TEST_DEST,
                depart_at=depart,
                arrive_at=depart + timedelta(hours=2),
                aircraft_type="A320",
                base_fare=price,
                currency="CAD",
            )
        )
        await db.execute(
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
        rows = []
        for index in range(seats):
            row_no = index // len(letters) + 10
            letter = letters[index % len(letters)]
            rows.append(
                {
                    "id": uuid.uuid4(),
                    "flight_id": flight_id,
                    "seat_no": f"{row_no}{letter}",
                    "row_no": row_no,
                    "seat_letter": letter,
                    "cabin": "economy",
                    "fare_class_id": fare_class_id,
                    "is_exit_row": False,
                    "price": price,
                    "status": "available",
                    "version": 0,
                }
            )
        await db.execute(insert(SeatInventory), rows)
        await db.commit()
        created.append(flight_id)
        return TestFlight(flight_id, [r["seat_no"] for r in rows], price)

    yield _make

    # Bookings reference flights with ondelete=RESTRICT, so leave rows behind if
    # a test booked something; the unique flight_no keeps them from colliding.
    for flight_id in created:
        try:
            await db.execute(delete(Flight).where(Flight.id == flight_id))
            await db.commit()
        except Exception:
            await db.rollback()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


async def hold_seat(client: AsyncClient, user: TestUser, flight_id, seat_no: str) -> str:
    response = await client.post(
        "/holds",
        headers=user.headers,
        json={"flight_id": str(flight_id), "seat_no": seat_no},
    )
    assert response.status_code == 201, response.text
    return response.json()["hold_id"]


def booking_body(hold_ids: list[str], card_token: str = APPROVE_TOKEN, **overrides) -> dict:
    body = {
        "hold_ids": hold_ids,
        "passengers": [
            {
                "given_name": "Ada",
                "family_name": "Lovelace",
                "dob": "1990-05-01",
                "passport_number": "AB1234567",
            }
            for _ in hold_ids
        ],
        "card_token": card_token,
    }
    body.update(overrides)
    return body


async def book(
    client: AsyncClient,
    user: TestUser,
    hold_ids: list[str],
    *,
    card_token: str = APPROVE_TOKEN,
    idempotency_key: str | None = None,
    body: dict | None = None,
):
    return await client.post(
        "/bookings",
        headers={**user.headers, "Idempotency-Key": idempotency_key or str(uuid.uuid4())},
        json=body or booking_body(hold_ids, card_token),
    )


__all__ = [
    "APPROVE_TOKEN",
    "DECLINE_TOKEN",
    "REFUND_FAILURE_TOKEN",
    "STRONG_PASSWORD",
    "TICKETING_FAILURE_TOKEN",
    "TIMEOUT_TOKEN",
    "TestFlight",
    "TestUser",
    "book",
    "booking_body",
    "hold_seat",
    "settings",
]
