# ADR-0002 — Conditional UPDATE for holds, `SELECT … FOR UPDATE` for the saga

**Status:** accepted · **Date:** 2026-09-10

## Context

Two users racing for the last seat is the same problem as a double-spend. The
textbook options are pessimistic locking (`SELECT … FOR UPDATE`) and optimistic
locking (a version column plus a retry loop). The interesting observation is
that the booking flow has *two* different shapes of contention and they want
different answers.

## Decision

**Acquiring a hold — one conditional `UPDATE`, no explicit lock:**

```sql
UPDATE seat_inventory
   SET status = 'held', held_by_user_id = :user, hold_id = :hold,
       hold_expires_at = now() + :ttl, version = version + 1
 WHERE flight_id = :flight AND seat_no = :seat
   AND (status = 'available' OR (status = 'held' AND hold_expires_at < now()))
RETURNING *;
```

The `UPDATE` takes the row lock itself. Concurrent writers serialize on it; the
loser then re-evaluates the `WHERE` against the winner's committed row under
`READ COMMITTED`, matches nothing, and gets zero rows. **Zero rows is the
answer** — no race window, no read-then-write gap, no retry loop, one round
trip.

**Confirming a booking — explicit `SELECT … FOR UPDATE`:**

```python
select(SeatInventory).where(...).order_by(SeatInventory.id).with_for_update()
```

The saga reads several rows and applies business logic in Python (are all these
holds still ours? are they on the same flight? has one lapsed?) before deciding.
That genuinely needs the rows pinned across the decision, which is what a
conditional `UPDATE` cannot express.

**Lock ordering.** Multi-seat bookings sort by primary key before locking. Two
concurrent bookings that want the same pair of seats in opposite order is the
textbook deadlock; a deterministic order turns it into a queue.

## Why not optimistic locking

Optimistic concurrency wins when conflicts are rare, because it avoids holding
locks. Here conflicts are the *expected* case on exactly the rows that matter —
the last seat on a full flight is precisely where everyone converges. Under that
contention an optimistic retry loop degrades: every racer does the work, all but
one throws it away, and the retries pile onto the same hot row.

The `version` column is kept anyway. It costs nothing, gives every write a cheap
change stamp, and makes the optimistic variant a small change if the contention
profile ever inverts.

## Why not `SERIALIZABLE`

Postgres's `SERIALIZABLE` would also be correct, and would let the code read
naively. But it pushes conflict handling into a retry loop for *serialization
failures* that the application must implement everywhere, and its predicate
locks cost throughput across the whole workload to solve a problem confined to
one row. Row locks under the default `READ COMMITTED` are the narrower tool.

## Consequences

**Good.** The hot path is a single statement, and losing a race is a normal
`409` rather than an exception. Correctness does not depend on retry logic being
right. Deadlocks are structurally prevented rather than handled.

**Costs.** Two mechanisms means two things to explain. Writers block rather than
failing fast, so a pathological hotspot shows up as latency rather than errors —
worth watching if this ever ran at real scale. And `FOR UPDATE` inside the saga
means row locks are held for the length of a transaction, which is why the saga
is several short transactions and *never* holds a lock across a call to the
payment gateway.

## Verification

`tests/concurrency/` races 20 real HTTP requests, each on its own database
connection, for a one-seat flight and asserts exactly one `201`. That test is
only meaningful if it fails when the locking is removed, so that was checked:
dropping the `takeable()` guard from the conditional `UPDATE` turns "one winner"
into twenty and fails four tests.

`load/oversell_proof.py` runs the full hold-then-book pipeline: 400 concurrent
attempts against 50 seats produce 50 confirmed bookings, 350 clean `409`s, and
zero 5xx. It asserts `booked <= capacity` rather than `== capacity` — utilisation
can legitimately fall short when the per-account hold cap binds, and a test that
demanded a sell-out would be asserting a different property than the one this
ADR is about.
