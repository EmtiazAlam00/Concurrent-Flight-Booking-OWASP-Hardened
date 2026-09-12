"""Drive a simulated card-testing attack against a running SkyLock.

Open http://localhost:8000/dash/security beside this and watch the feed fill up
in real time. That is the demo: security work is invisible until something makes
it visible.

The attack it models is the real one. An attacker with a list of stolen card
numbers needs to know which are still live. Airline bookings are ideal for
testing them — high value, instantly resellable, and an authorize/void flow
gives a cheap yes/no oracle. So they cycle many cards through one or a few
accounts and watch for the first approval.

    python -m scripts.simulate_carding [--base-url http://localhost:8000]
"""

import argparse
import asyncio
import logging
import uuid

import httpx

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("demo.carding")

DECLINE = "0002"
APPROVE = "0000"
PASSWORD = "correct-horse-battery-staple"


def card(suffix: str) -> str:
    """A distinct card token whose last four characters drive the fake gateway."""
    return f"tok_test_{uuid.uuid4().hex[:8]}{suffix}"


async def register(client: httpx.AsyncClient, label: str) -> dict[str, str]:
    email = f"{label}-{uuid.uuid4().hex[:8]}@example.com"
    response = await client.post("/auth/register", json={"email": email, "password": PASSWORD})
    if response.status_code == 429:
        raise SystemExit(
            "Registration is rate limited (10 new accounts per hour per IP) and this "
            "demo needs a handful.\n"
            "That limit doing its job is arguably the more interesting demo, but to "
            "run this one again either wait for the window, or clear the counter:\n"
            "  docker compose exec redis redis-cli --scan --pattern 'rl:register:*' "
            "| xargs -r docker compose exec -T redis redis-cli del"
        )
    response.raise_for_status()
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def find_a_flight(client: httpx.AsyncClient) -> tuple[str, list[str]]:
    """Any seeded flight with free seats will do."""
    from datetime import UTC, datetime, timedelta

    for days in range(0, 10):
        day = (datetime.now(UTC) + timedelta(days=days)).date().isoformat()
        for origin, destination in (
            ("YOW", "YYZ"),
            ("YYZ", "YVR"),
            ("JFK", "LHR"),
            ("SFO", "JFK"),
            ("LHR", "SFO"),
            ("YVR", "YUL"),
            ("ORD", "SFO"),
            ("YUL", "LHR"),
        ):
            response = await client.get(
                "/flights/search",
                params={"origin": origin, "destination": destination, "departure_date": day},
            )
            items = response.json().get("items", []) if response.status_code == 200 else []
            for item in items:
                if item["seats_available"] > 12:
                    seats = await client.get(f"/flights/{item['id']}/seats")
                    free = [s["seat_no"] for s in seats.json()["seats"] if s["available"]]
                    return item["id"], free
    raise SystemExit(
        "No seeded flight with free seats. Run:\n"
        "  python -m scripts.seed_reference && python -m scripts.seed_flights --scale demo"
    )


async def attempt(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    flight_id: str,
    seat_no: str,
    card_token: str,
) -> tuple[int, str]:
    held = await client.post(
        "/holds", headers=headers, json={"flight_id": flight_id, "seat_no": seat_no}
    )
    if held.status_code != 201:
        return held.status_code, held.json().get("code", "?")

    hold_id = held.json()["hold_id"]
    booked = await client.post(
        "/bookings",
        headers={**headers, "Idempotency-Key": str(uuid.uuid4())},
        json={
            "hold_ids": [hold_id],
            "passengers": [{"given_name": "Test", "family_name": "Buyer"}],
            "card_token": card_token,
        },
    )
    body = (
        booked.json()
        if booked.headers.get("content-type", "").startswith(
            ("application/json", "application/problem")
        )
        else {}
    )

    if booked.status_code != 201:
        # Release the hold after a failed attempt. A real attacker would not
        # leave seats locked behind them, and without this the *hold cap* stops
        # the run before the fraud rules get a chance to — which would be the
        # right behaviour but the wrong demo.
        await client.delete(f"/holds/{hold_id}", headers=headers)

    return booked.status_code, body.get("code", body.get("state", "?"))


async def main(base_url: str) -> None:
    # The request rate limiter and the fraud rules are different controls. When
    # demo runs are back to back the limiter fires first, which is correct but
    # obscures what this script is here to show — so we call it out.
    any_rate_limited = False

    async with httpx.AsyncClient(base_url=base_url, timeout=30) as client:
        health = await client.get("/health")
        if health.status_code != 200:
            raise SystemExit(f"{base_url} is not healthy — is the API running?")

        flight_id, seats = await find_a_flight(client)
        logger.info("Target flight %s with %d free seats", flight_id[:8], len(seats))
        logger.info("Watch: %s/dash/security\n", base_url)

        seat_pool = iter(seats)

        # --- phase 1: normal traffic, for contrast --------------------------
        logger.info("Phase 1 — a legitimate customer books a seat")
        legit = await register(client, "legit")
        status, code = await attempt(client, legit, flight_id, next(seat_pool), card(APPROVE))
        logger.info("  -> %s %s", status, code)
        logger.info("  No security events. This is what normal looks like.")

        # --- phase 2: one account, many stolen cards ------------------------
        logger.info("\nPhase 2 — one account works through a list of stolen cards")
        attacker = await register(client, "attacker")
        for index in range(4):
            token = card(DECLINE)
            status, code = await attempt(client, attacker, flight_id, next(seat_pool), token)
            logger.info("  card %d (…%s) -> %s %s", index + 1, token[-4:], status, code)
            await asyncio.sleep(0.25)
        if any_rate_limited:
            logger.info("  (Some attempts hit the request rate limit — a separate control.")
            logger.info("   Wait a minute between demo runs to see the fraud rules alone.)")
        logger.info("  Two rules combine to stop this: 4+ distinct cards on one")
        logger.info("  account (40) plus booking faster than a human checkout (25)")
        logger.info("  is 65, past the block threshold of 60.")

        # --- phase 3: the card that would have worked ------------------------
        logger.info("\nPhase 3 — the attacker reaches a card that is actually live")
        status, code = await attempt(client, attacker, flight_id, next(seat_pool), card(APPROVE))
        logger.info("  -> %s %s", status, code)
        if status == 403:
            logger.info("  It never reached the payment gateway, so the attacker")
            logger.info("  learns nothing about whether that card is good — which is")
            logger.info("  the entire point of card testing.")

        # --- phase 4: rotating accounts --------------------------------------
        logger.info("\nPhase 4 — the attacker rotates to fresh accounts, same card")
        shared = card(DECLINE)
        for index in range(3):
            mule = await register(client, f"mule{index}")
            status, code = await attempt(client, mule, flight_id, next(seat_pool), shared)
            any_rate_limited = any_rate_limited or status == 429
            logger.info("  fresh account %d -> %s %s", index + 1, status, code)
        logger.info("  A card seen across multiple accounts is its own rule, so")
        logger.info("  burning accounts does not reset the attacker's score.")
        if any_rate_limited:
            logger.info("\n  Note: some attempts returned 429. That is the request rate limiter,")
            logger.info("  not the fraud engine. Wait ~60s between runs for a clean demo.")

    await summarize()
    logger.info(
        "\nThe security feed at %s/dash/security shows each detection with the "
        "rules it hit and the counts that tripped them.",
        base_url,
    )


async def summarize() -> None:
    """Report what the detector recorded *during this run*, from Postgres."""
    from collections import Counter
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import select

    from app.db import session_scope
    from app.domain.models import SecurityEvent

    # Scoped to the last few minutes so repeated demo runs don't inflate the
    # numbers with each other's events.
    since = datetime.now(UTC) - timedelta(minutes=3)
    async with session_scope() as session:
        rows = list(
            (
                await session.scalars(
                    select(SecurityEvent)
                    .where(
                        SecurityEvent.event_type.like("CARDING%"),
                        SecurityEvent.occurred_at >= since,
                    )
                    .order_by(SecurityEvent.id.desc())
                    .limit(500)
                )
            ).all()
        )

    if not rows:
        logger.info("\nNo carding events recorded.")
        return

    by_type = Counter(r.event_type for r in rows)
    rules = Counter(rule for r in rows for rule in r.detail.get("rules_hit", []))
    if any("rule" in r.detail for r in rows):
        rules.update(r.detail["rule"] for r in rows if "rule" in r.detail)

    logger.info("\nRecorded %d carding events in this run:", len(rows))
    for event_type, count in by_type.most_common():
        logger.info("  %-20s %d", event_type, count)
    logger.info("Rules that fired:")
    for rule, count in rules.most_common():
        logger.info("  %-28s %dx", rule, count)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://localhost:8000")
    args = parser.parse_args()
    asyncio.run(main(args.base_url))
