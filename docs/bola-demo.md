# BOLA: the attack, the damage, the fix

Broken Object Level Authorization is #1 on the OWASP API Security Top 10. It is
the easiest serious flaw to introduce and the hardest to catch in review,
because nothing looks wrong: the endpoint works, the happy-path tests pass, and
the only defect is a check nobody wrote.

This document shows the vulnerable version, what it actually leaks, and what
closes it — with real output, not description.

Reproduce any of it yourself:

```bash
make up && make seed
python -m scripts.exploit_bola          # exit 0 on main
```

---

## The vulnerable version

Eight lines. It authenticates the caller, looks the booking up by reference, and
returns it:

```python
async def owned_booking(request, booking_ref, user, db) -> Booking:
    booking = await db.scalar(select(Booking).where(Booking.ref == booking_ref.upper()))
    if booking is None:
        raise NotFound("No such booking")
    return booking
```

The caller *is* authenticated — a valid token is required to reach this code at
all. That is exactly what makes the bug survive review. Authentication answers
"who are you"; authorization answers "may you have *this object*". Conflating
them is the whole vulnerability class.

## What it leaks

Run against that version, the exploit script gets everything:

```
1. A victim books a seat and supplies their passport details.
   Booking reference: UWQGWJ  (seat 1F)

2. An attacker registers their own account and asks for that PNR.

   [LEAK] GET    UWQGWJ           -> 200    read the booking (PII)
   [LEAK] GET    audit            -> 200    read its full history
   [LEAK] PATCH  UWQGWJ           -> 200    rename the passenger
   [LEAK] POST   cancel           -> 200    cancel someone else's flight

3. Can the endpoint be used to tell real PNRs from fake ones?
   real-but-not-mine UWQGWJ -> 200
   nonexistent       ZZZZZZ -> 404
   DIFFERENT responses: the endpoint confirms which references exist.

====================================================================
VULNERABLE
  GET /bookings/UWQGWJ returned 200
    {"ref":"UWQGWJ","state":"CONFIRMED","flight_no":"US100","src_iata":"JFK",
     "dst_iata":"LHR","depart_at":"2026-09-11T07:05:00Z","total_amount":"1508.89"…
  POST /bookings/UWQGWJ/cancel returned 200
    {"ref":"UWQGWJ","state":"CANCELLED","refunded":true,"seats_released":1}
  Booking references are enumerable.
```

Worth being precise about the damage, because "an IDOR" undersells it:

- **PII disclosure** — passenger name, passport digits, and a full itinerary. An
  itinerary says when someone's home is empty.
- **Full history** — the audit trail exposes every state change on the booking.
- **Tampering** — `PATCH` rewrites the passenger name on someone else's ticket.
- **Destruction** — `POST /cancel` cancels a stranger's flight *and refunds it*,
  releasing their seat back into inventory. A read vulnerability turned into a
  denial-of-travel one, because the same missing check guards every route.
- **Enumeration** — a real-but-not-yours PNR returns `200` where a nonexistent
  one returns `404`, so the endpoint confirms which references exist. A PNR is
  six characters from a 31-character alphabet; an oracle makes brute-forcing
  live bookings practical.

## The fix

```python
booking = await db.scalar(
    select(Booking).where(
        Booking.ref == booking_ref.upper(),
        Booking.user_id == user.id,  # <- the authorization, inlined in the query
    )
)
if booking is None:
    await _deny(request, user.id, "booking", booking_ref)
    raise NotFound("No such booking")
```

Three things changed, and each is load-bearing:

1. **Ownership moved into the `WHERE` clause.** Not a `if booking.user_id !=
   user.id` after the load — one query, no window between reading and deciding,
   and no `if` for a later refactor to quietly drop.
2. **404, not 403.** Unauthorized and nonexistent are now byte-identical, so the
   oracle is gone.
3. **The denial is recorded.** `AUTHZ_DENIED` at `MEDIUM` on the security feed,
   so probing is visible rather than silent.

The structural part is that handlers declare `booking: OwnedBooking` and never
receive a raw `booking_ref`. Forgetting the check is not something you can do by
omission — it requires changing the function signature.

## What catches it

Against the vulnerable version, the suite fails and names every exposed route:

```
FAILED test_every_booking_scoped_route_is_ownership_checked
E   AssertionError: BOLA exposure:
E       GET   /bookings/{booking_ref}:        another user got 200, expected 404
E       GET   /bookings/{booking_ref}/audit:  another user got 200, expected 404
E       PATCH /bookings/{booking_ref}:        another user got 200, expected 404
E       POST  /bookings/{booking_ref}/cancel: another user got 200, expected 404

FAILED test_someone_elses_booking_and_a_fake_one_are_indistinguishable
FAILED test_a_bola_attempt_leaves_a_security_event
E   AssertionError: an authorization denial must be recorded
```

That test does not enumerate routes by hand. It walks `app.routes`, finds
everything parameterized by `{booking_ref}`, and checks each against a
non-owner and an anonymous caller. **A new booking-scoped endpoint that forgets
the dependency fails CI the day it is written**, with no one remembering to
extend a list.

It has its own guard, `test_the_route_inventory_is_not_empty`, because a matrix
that silently discovers zero routes would pass while testing nothing. That guard
earned itself immediately: the first implementation iterated `app.routes` flat,
and this FastAPI version nests included routers behind a wrapper object, so it
found nothing and "passed".

## Reproducing the vulnerable version

The exploit script lives on `main` because it is a test of the defense — it
exits 0 when the target is safe and 1 when it is not, so it doubles as a smoke
test against a deployed environment.

To watch it fail, reintroduce the flaw on a branch:

```bash
git switch -c demo/bola-vulnerable

# replace the body of owned_booking() in app/security/authz.py with the
# vulnerable version above, then:
uvicorn app.main:app --port 8001                 # against the same datastores
python -m scripts.exploit_bola --base-url http://localhost:8001   # exits 1
pytest tests/security/test_authz_matrix.py -q                     # 3 failures

git switch main
```

## Why this is not a runtime flag

The obvious alternative is `if settings.insecure_mode: skip_check()`, toggled by
an environment variable. That was rejected deliberately.

A switch that disables authorization **is itself the finding**. It is one
misconfiguration, one bad merge, or one copied `.env` away from production, and
it inverts the property that makes the fix trustworthy — that a handler
*cannot* receive an unchecked reference. "Authorization can be turned off with
an environment variable" is not a sentence that belongs in a repository about
API security.

Git history costs nothing and carries no such risk.

→ [ADR-0005](ADR-0005-object-level-authorization.md) · [SECURITY.md](../SECURITY.md)
