# ADR-0005 — Ownership lives in the WHERE clause, and answers 404

**Status:** accepted · **Date:** 2026-09-10

## Context

Broken Object Level Authorization is #1 on the OWASP API Security Top 10 because
it is the easiest vulnerability to introduce and the hardest to spot in review:
the endpoint works, the tests pass, and the only thing wrong is a check nobody
wrote. Changing `GET /bookings/K7R2MQ` to someone else's PNR reads their name,
passport digits, and itinerary.

## Decision

**Ownership is enforced by the query, in a dependency, and handlers never see a
raw identifier.**

```python
async def owned_booking(booking_ref, user, db) -> Booking:
    booking = await db.scalar(
        select(Booking).where(Booking.ref == booking_ref, Booking.user_id == user.id)
    )
    if booking is None:
        raise NotFound("No such booking")
    return booking
```

Route handlers declare `booking: OwnedBooking`. There is no version of
`get_booking` that receives a `booking_ref` string, so forgetting the check is
not something you can do by omission — it requires changing the signature.

Three properties, each deliberate:

**One query, not fetch-then-check.** `WHERE id = :id AND user_id = :me` has no
window between loading and deciding, and no `if` for a later refactor to drop.

**404, not 403.** A `403` on a real-but-not-yours booking and a `404` on a
nonexistent one turns the endpoint into an existence oracle. A PNR is six
characters from a 31-character alphabet — small enough that confirming which
ones are real is worth an attacker's time. Unauthorized and nonexistent return
byte-identical responses, and there is a test asserting exactly that.

**Every denial is logged.** `AUTHZ_DENIED` at `MEDIUM`, carrying the resource
and the actor, so probing shows up on the security feed instead of being
invisible.

List endpoints get the same treatment: `WHERE user_id = :me` is in the query,
not applied afterwards in Python.

## The test that matters more than the fix

`test_every_booking_scoped_route_is_ownership_checked` does not enumerate routes
by hand. It walks `app.routes`, finds everything parameterized by
`{booking_ref}`, and asserts each returns `404` for another user and `401` for
an anonymous caller. **A new booking-scoped endpoint that forgets the dependency
fails the suite the day it is written**, without anyone remembering to extend a
list.

That test has its own guard — `test_the_route_inventory_is_not_empty` — because
a matrix that silently discovers zero routes would pass while testing nothing.
That guard earned itself immediately: the first implementation iterated
`app.routes` flat, and this FastAPI version nests included routers behind a
wrapper, so it found nothing and "passed".

## Why the vulnerable version is a branch, not a flag

The brief called for building the vulnerable version, demonstrating the attack,
then showing the fix. The attack lives on `main` as `scripts/exploit_bola.py`,
because an exploit that verifies the *defense* belongs with the defense — it
exits 0 when the target is safe and 1 when it is not. The vulnerable variant and
a full transcript of what it leaks are in [bola-demo.md](bola-demo.md), and
reintroducing it on a `demo/bola-vulnerable` branch is one edit.

It is deliberately **not** an `INSECURE_MODE` environment variable on `main`. A
switch that disables authorization is itself the finding: it is one
misconfiguration away from production, and "authorization can be turned off with
an env var" is the wrong sentence to have in a repository about API security.

## Consequences

**Good.** The vulnerability class is closed structurally rather than by
vigilance. New endpoints inherit the protection or fail CI.

**Costs.** Genuine 404s and authorization failures are indistinguishable in the
logs from the caller's side, so debugging "why can't I see my booking?" means
reading the security event rather than the status code. Admin tooling that
legitimately needs cross-user access cannot use these dependencies and needs its
own explicitly-scoped path — currently only `/admin/security-events`, gated on
an admin scope, with its own denial logging.
