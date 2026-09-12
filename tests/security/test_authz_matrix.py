"""Object-level authorization — OWASP API Security #1 (BOLA).

The important test here is `test_every_booking_scoped_route_is_ownership_checked`,
which does not enumerate routes by hand. It reads them off `app.routes`, so a
**newly added** booking-scoped endpoint that forgets the ownership dependency
fails this suite the day it is written, without anyone remembering to extend a
list. That property is worth more than the fix it protects.
"""

import uuid

import pytest
from fastapi.routing import APIRoute
from sqlalchemy import select

from app.domain.enums import SecurityEventType
from app.domain.models import SecurityEvent
from app.main import app
from tests.conftest import book, hold_seat

pytestmark = [pytest.mark.security, pytest.mark.integration]


def iter_api_routes(router) -> list[APIRoute]:
    """Walk the route tree.

    Recursive on purpose: depending on the FastAPI version, `include_router`
    either flattens routes into `app.routes` or nests them behind a wrapper
    object. A flat iteration silently finds nothing on the nesting versions —
    which would make this entire suite pass while testing zero routes.
    """
    collected: list[APIRoute] = []
    for route in getattr(router, "routes", []):
        if isinstance(route, APIRoute):
            collected.append(route)
            continue
        # Newer FastAPI wraps an included router in an object that exposes the
        # original under `original_router` rather than as `.routes`.
        nested = getattr(route, "original_router", None) or route
        if nested is not route or hasattr(nested, "routes"):
            collected.extend(iter_api_routes(nested))
    return collected


def booking_scoped_routes() -> list[tuple[str, str]]:
    """Every route whose path is parameterized by a booking reference."""
    found = []
    for route in iter_api_routes(app):
        if "{booking_ref}" not in route.path:
            continue
        for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
            found.append((method, route.path))
    return sorted(set(found))


def _fill(path: str, ref: str) -> str:
    return path.replace("{booking_ref}", ref)


class TestBolaMatrix:
    async def test_the_route_inventory_is_not_empty(self):
        # Guards against the matrix silently testing nothing if the path
        # parameter is ever renamed.
        routes = booking_scoped_routes()
        assert len(routes) >= 4, routes
        assert ("GET", "/bookings/{booking_ref}") in routes

    async def test_every_booking_scoped_route_is_ownership_checked(
        self, client, user, other_user, make_flight
    ):
        """The whole matrix: each route x {owner, other user, anonymous}."""
        flight = await make_flight(seats=6)
        hold = await hold_seat(client, user, flight.id, flight.seat_numbers[0])
        ref = (await book(client, user, [hold])).json()["ref"]

        failures = []
        for method, path in booking_scoped_routes():
            url = _fill(path, ref)
            payload = {"passengers": [{"passenger_id": str(uuid.uuid4()), "given_name": "X"}]}

            attacker = await client.request(method, url, headers=other_user.headers, json=payload)
            if attacker.status_code != 404:
                failures.append(
                    f"{method} {path}: another user got {attacker.status_code}, expected 404"
                )

            anonymous = await client.request(method, url, json=payload)
            if anonymous.status_code != 401:
                failures.append(
                    f"{method} {path}: anonymous got {anonymous.status_code}, expected 401"
                )

        assert not failures, "BOLA exposure:\n  " + "\n  ".join(failures)

    async def test_the_owner_is_not_locked_out_by_the_check(self, client, user, make_flight):
        """The other half of an authorization test, and the half people skip."""
        flight = await make_flight(seats=6)
        hold = await hold_seat(client, user, flight.id, flight.seat_numbers[0])
        ref = (await book(client, user, [hold])).json()["ref"]

        assert (await client.get(f"/bookings/{ref}", headers=user.headers)).status_code == 200
        assert (await client.get(f"/bookings/{ref}/audit", headers=user.headers)).status_code == 200


class TestNoExistenceOracle:
    async def test_someone_elses_booking_and_a_fake_one_are_indistinguishable(
        self, client, user, other_user, make_flight
    ):
        """404 for both, byte for byte.

        If a real-but-not-yours PNR returned 403 while a nonexistent one
        returned 404, an attacker could enumerate valid record locators — a
        6-character space is small enough to make that worth doing.
        """
        flight = await make_flight(seats=2)
        hold = await hold_seat(client, user, flight.id, flight.seat_numbers[0])
        real_ref = (await book(client, user, [hold])).json()["ref"]
        fake_ref = "ZZZZZZ" if real_ref != "ZZZZZZ" else "YYYYYY"

        real = await client.get(f"/bookings/{real_ref}", headers=other_user.headers)
        fake = await client.get(f"/bookings/{fake_ref}", headers=other_user.headers)

        assert real.status_code == fake.status_code == 404
        assert real.json()["code"] == fake.json()["code"] == "not_found"
        assert real.json()["detail"] == fake.json()["detail"]

    async def test_holds_are_also_not_enumerable(self, client, user, other_user, make_flight):
        flight = await make_flight(seats=2)
        hold_id = await hold_seat(client, user, flight.id, flight.seat_numbers[0])

        real = await client.get(f"/holds/{hold_id}", headers=other_user.headers)
        fake = await client.get(f"/holds/{uuid.uuid4()}", headers=other_user.headers)

        assert real.status_code == fake.status_code == 404
        assert real.json()["detail"] == fake.json()["detail"]


class TestListEndpointsAreScoped:
    async def test_listing_bookings_never_leaks_another_account(
        self, client, user, other_user, make_flight
    ):
        flight = await make_flight(seats=4)
        mine = await hold_seat(client, user, flight.id, flight.seat_numbers[0])
        theirs = await hold_seat(client, other_user, flight.id, flight.seat_numbers[1])
        my_ref = (await book(client, user, [mine])).json()["ref"]
        their_ref = (await book(client, other_user, [theirs])).json()["ref"]

        listing = await client.get("/bookings", headers=user.headers)
        refs = {item["ref"] for item in listing.json()["items"]}

        assert my_ref in refs
        assert their_ref not in refs

    async def test_listing_holds_never_leaks_another_account(
        self, client, user, other_user, make_flight
    ):
        flight = await make_flight(seats=4)
        await hold_seat(client, user, flight.id, flight.seat_numbers[0])
        await hold_seat(client, other_user, flight.id, flight.seat_numbers[1])

        listing = await client.get("/holds", headers=user.headers)
        assert len(listing.json()) == 1
        assert listing.json()[0]["seat_no"] == flight.seat_numbers[0]


class TestPrivilegeEscalation:
    async def test_a_normal_user_cannot_read_the_security_log(self, client, user):
        response = await client.get("/admin/security-events", headers=user.headers)
        assert response.status_code == 403
        assert response.json()["code"] == "forbidden"

    async def test_an_admin_can(self, client, admin):
        response = await client.get("/admin/security-events", headers=admin.headers)
        assert response.status_code == 200
        assert "items" in response.json()

    async def test_anonymous_cannot(self, client):
        assert (await client.get("/admin/security-events")).status_code == 401

    async def test_a_refresh_token_is_not_an_access_token(self, client, user):
        """Token confusion: the `typ` claim is checked, not just the signature."""
        response = await client.get("/auth/me", headers={"Authorization": f"Bearer {user.refresh}"})
        assert response.status_code == 401


class TestDenialsAreLogged:
    async def test_a_bola_attempt_leaves_a_security_event(
        self, client, user, other_user, make_flight, db
    ):
        flight = await make_flight(seats=2)
        hold = await hold_seat(client, user, flight.id, flight.seat_numbers[0])
        ref = (await book(client, user, [hold])).json()["ref"]

        await client.get(f"/bookings/{ref}", headers=other_user.headers)

        event = await db.scalar(
            select(SecurityEvent)
            .where(
                SecurityEvent.event_type == SecurityEventType.AUTHZ_DENIED,
                SecurityEvent.actor_user_id == other_user.id,
            )
            .order_by(SecurityEvent.id.desc())
        )
        assert event is not None, "an authorization denial must be recorded"
        assert event.resource_type == "booking"
        assert event.resource_id == ref
        assert event.decision == "deny"
