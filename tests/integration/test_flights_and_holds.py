"""Search, seat maps, holds, and the input validation that guards them."""

import uuid
from datetime import UTC, date, datetime, timedelta

import pytest
from sqlalchemy import select, update

from app.config import settings
from app.domain.enums import SeatStatus
from app.domain.models import SeatInventory

pytestmark = pytest.mark.integration


class TestHealth:
    async def test_reports_both_datastores(self, client):
        response = await client.get("/health")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["checks"] == {"database": "ok", "redis": "ok"}


class TestSearch:
    async def test_finds_a_flight_on_the_right_day(self, client, make_flight):
        flight = await make_flight(seats=4, depart_in_days=5)
        departure = (datetime.now(UTC) + timedelta(days=5)).date()

        response = await client.get(
            "/flights/search",
            params={"origin": "XAA", "destination": "XBB", "departure_date": departure.isoformat()},
        )
        assert response.status_code == 200
        ids = [item["id"] for item in response.json()["items"]]
        assert str(flight.id) in ids

    async def test_availability_matches_the_seat_map(self, client, make_flight, user):
        flight = await make_flight(seats=4, depart_in_days=6)
        departure = (datetime.now(UTC) + timedelta(days=6)).date()

        await client.post(
            "/holds",
            headers=user.headers,
            json={"flight_id": str(flight.id), "seat_no": flight.seat_numbers[0]},
        )

        search = await client.get(
            "/flights/search",
            params={"origin": "XAA", "destination": "XBB", "departure_date": departure.isoformat()},
        )
        found = next(i for i in search.json()["items"] if i["id"] == str(flight.id))
        seat_map = await client.get(f"/flights/{flight.id}/seats")

        # Search and the seat map must agree; they share one `takeable` predicate.
        assert found["seats_available"] == seat_map.json()["available_seats"] == 3

    async def test_pagination_is_capped(self, client):
        response = await client.get(
            "/flights/search",
            params={
                "origin": "XAA",
                "destination": "XBB",
                "departure_date": date.today().isoformat(),
                "page_size": 5000,
            },
        )
        assert response.status_code == 422, "an uncapped page size is a DoS parameter"

    @pytest.mark.parametrize(
        "params",
        [
            {"origin": "TOOLONG", "destination": "XBB", "departure_date": "2026-01-01"},
            {"origin": "X1A", "destination": "XBB", "departure_date": "2026-01-01"},
            {"origin": "XAA", "destination": "XBB", "departure_date": "not-a-date"},
            {"origin": "XAA' OR 1=1--", "destination": "XBB", "departure_date": "2026-01-01"},
        ],
    )
    async def test_malformed_input_is_rejected_at_the_edge(self, client, params):
        response = await client.get("/flights/search", params=params)
        assert response.status_code == 422
        assert response.json()["code"] == "validation_failed"

    async def test_an_unknown_flight_is_404(self, client):
        assert (await client.get(f"/flights/{uuid.uuid4()}")).status_code == 404


class TestSeatMap:
    async def test_shape(self, client, make_flight):
        flight = await make_flight(seats=6)
        response = await client.get(f"/flights/{flight.id}/seats")
        body = response.json()

        assert body["total_seats"] == 6
        assert body["available_seats"] == 6
        assert {s["seat_no"] for s in body["seats"]} == set(flight.seat_numbers)
        assert all(s["available"] for s in body["seats"])


class TestHolds:
    async def test_hold_then_release_frees_the_seat(self, client, user, make_flight, db):
        flight = await make_flight(seats=2)
        seat_no = flight.seat_numbers[0]

        created = await client.post(
            "/holds",
            headers=user.headers,
            json={"flight_id": str(flight.id), "seat_no": seat_no},
        )
        assert created.status_code == 201
        hold_id = created.json()["hold_id"]
        assert 0 < created.json()["seconds_remaining"] <= settings.hold_ttl_seconds

        released = await client.delete(f"/holds/{hold_id}", headers=user.headers)
        assert released.status_code == 204

        seat = await db.scalar(
            select(SeatInventory).where(
                SeatInventory.flight_id == flight.id, SeatInventory.seat_no == seat_no
            )
        )
        assert seat.status == SeatStatus.AVAILABLE
        assert seat.hold_id is None

    async def test_releasing_twice_is_404(self, client, user, make_flight):
        flight = await make_flight(seats=2)
        hold_id = (
            await client.post(
                "/holds",
                headers=user.headers,
                json={"flight_id": str(flight.id), "seat_no": flight.seat_numbers[0]},
            )
        ).json()["hold_id"]

        assert (await client.delete(f"/holds/{hold_id}", headers=user.headers)).status_code == 204
        assert (await client.delete(f"/holds/{hold_id}", headers=user.headers)).status_code == 404

    async def test_holding_a_nonexistent_seat_is_404_not_409(self, client, user, make_flight):
        """A missing seat and a taken seat are different answers."""
        flight = await make_flight(seats=2)
        response = await client.post(
            "/holds",
            headers=user.headers,
            json={"flight_id": str(flight.id), "seat_no": "99Z"},
        )
        assert response.status_code == 404

    async def test_active_holds_are_capped_per_account(self, client, user, make_flight):
        """Squatting on inventory is a denial-of-inventory attack."""
        cap = settings.max_active_holds_per_user
        flight = await make_flight(seats=cap + 2)

        for seat_no in flight.seat_numbers[:cap]:
            response = await client.post(
                "/holds",
                headers=user.headers,
                json={"flight_id": str(flight.id), "seat_no": seat_no},
            )
            assert response.status_code == 201, response.text

        over = await client.post(
            "/holds",
            headers=user.headers,
            json={"flight_id": str(flight.id), "seat_no": flight.seat_numbers[cap]},
        )
        assert over.status_code == 409
        assert over.json()["code"] == "too_many_holds"

    async def test_an_expired_hold_does_not_count_toward_the_cap(
        self, client, user, make_flight, db
    ):
        cap = settings.max_active_holds_per_user
        flight = await make_flight(seats=cap + 2)
        for seat_no in flight.seat_numbers[:cap]:
            await client.post(
                "/holds",
                headers=user.headers,
                json={"flight_id": str(flight.id), "seat_no": seat_no},
            )

        await db.execute(
            update(SeatInventory)
            .where(
                SeatInventory.flight_id == flight.id,
                SeatInventory.seat_no == flight.seat_numbers[0],
            )
            .values(hold_expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        await db.commit()

        response = await client.post(
            "/holds",
            headers=user.headers,
            json={"flight_id": str(flight.id), "seat_no": flight.seat_numbers[cap]},
        )
        assert response.status_code == 201

    async def test_holding_requires_authentication(self, client, make_flight):
        flight = await make_flight(seats=2)
        response = await client.post(
            "/holds", json={"flight_id": str(flight.id), "seat_no": flight.seat_numbers[0]}
        )
        assert response.status_code == 401

    @pytest.mark.parametrize("seat_no", ["", "ABC", "1", "999ZZ", "1A; DROP TABLE seats"])
    async def test_malformed_seat_numbers_are_rejected(self, client, user, make_flight, seat_no):
        flight = await make_flight(seats=2)
        response = await client.post(
            "/holds",
            headers=user.headers,
            json={"flight_id": str(flight.id), "seat_no": seat_no},
        )
        assert response.status_code == 422

    async def test_unknown_fields_are_rejected(self, client, user, make_flight):
        """extra='forbid' — a client cannot smuggle in an unexpected field."""
        flight = await make_flight(seats=2)
        response = await client.post(
            "/holds",
            headers=user.headers,
            json={
                "flight_id": str(flight.id),
                "seat_no": flight.seat_numbers[0],
                "price": "0.01",
            },
        )
        assert response.status_code == 422


class TestDashboard:
    async def test_requires_credentials(self, client):
        assert (await client.get("/dash")).status_code == 401

    async def test_rejects_bad_credentials(self, client):
        response = await client.get("/dash", auth=("dash", "wrong-password"))
        assert response.status_code == 401

    async def test_renders_for_an_operator(self, client):
        response = await client.get(
            "/dash", auth=(settings.dashboard_user, settings.dashboard_password)
        )
        assert response.status_code == 200
        assert "SkyLock" in response.text

    @pytest.mark.parametrize("path", ["/dash/holds", "/dash/audit", "/dash/security"])
    async def test_every_page_renders(self, client, path):
        response = await client.get(
            path, auth=(settings.dashboard_user, settings.dashboard_password)
        )
        assert response.status_code == 200

    @pytest.mark.parametrize("path", ["/dash/holds/rows", "/dash/security/rows"])
    async def test_htmx_fragments_render(self, client, path):
        response = await client.get(
            path, auth=(settings.dashboard_user, settings.dashboard_password)
        )
        assert response.status_code == 200
        assert "<html" not in response.text.lower(), "fragments must not be whole pages"

    async def test_the_dashboard_exposes_no_write_routes(self):
        """Structural assertion: the dashboard observes, it never mutates."""
        from app.api import dashboard as dashboard_module

        for route in dashboard_module.router.routes:
            assert route.methods <= {"GET", "HEAD"}, f"{route.path} is not read-only"
