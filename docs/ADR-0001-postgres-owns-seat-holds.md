# ADR-0001 — Postgres owns seat holds; Redis holds no truth

**Status:** accepted · **Date:** 2026-09-10

## Context

A seat hold reserves a seat for ~10 minutes during checkout and then releases
itself. The obvious implementation is a Redis key with a TTL: Redis expires it
for you, and the code is three lines.

That obvious implementation is wrong, and it is worth being precise about why.

## Decision

`seat_inventory` in Postgres is the single source of truth for hold state:
`status`, `held_by_user_id`, `hold_id`, `hold_expires_at`. **Expiry is evaluated
lazily, in the `WHERE` clause of every query that asks whether a seat can be
taken:**

```sql
status = 'available' OR (status = 'held' AND hold_expires_at < now())
```

That predicate is defined once (`app/services/holds.py::takeable`) and used by
the hold path, search, and the seat map, so those three can never disagree about
what "free" means.

The background sweep (`app/jobs/sweep.py`) only normalizes rows whose hold has
already lapsed. It is a janitor, not the mechanism.

Redis keeps derived state only: rate-limit windows, card-testing velocity
counters. Losing it degrades those features and corrupts nothing.

## Why not Redis TTL keys

**A TTL key that vanishes on its own creates a split brain.** Redis drops the
key; Postgres still says `status='held'`. Two systems now disagree about who
owns seat 14C and there is no principled way to decide which is right. This is
not hypothetical — it happens on eviction under `maxmemory`, on restart without
persistence, and on failover to a replica that hadn't caught up.

Three further problems:

1. **Redis expiry is lazy and approximate.** A key is removed when accessed
   after expiry or when the background sampler happens to reach it. "Expired"
   and "gone" are not the same instant, so a hold could still block a booking
   after its TTL.
2. **The hold has to be transactional with the booking.** Confirming a booking
   flips a seat from `held` to `booked` and inserts a ticket. If the hold lives
   in Redis, that operation spans two systems with no shared transaction, and
   the failure modes multiply.
3. **It makes the cleanup job load-bearing.** If availability depends on the
   sweep having run, then a stuck job silently sells nothing — or worse, oversells.

## Consequences

**Good.** Correctness does not depend on the background job. Stop the sweep for
an hour and nothing oversells, no booking breaks, no seat is wrongly blocked;
the only effect is that some rows still say `held` when they mean `available`.
That property is directly testable, and it is
(`test_an_expired_hold_frees_the_seat_before_the_sweep_runs` never calls the
sweep at all).

Redis is now genuinely optional to correctness, which is what lets the rate
limiter and the fraud detector fail open without risking data integrity.

**Costs.** Every availability query carries an extra predicate and depends on a
partial index (`ix_seat_hold_expiry`). Rows can sit in a stale `held` state
between sweeps, so anything reading `status` directly — the dashboard, ad-hoc
SQL — must use `takeable()` rather than `status = 'available'`. That is a real
footgun, and the reason the predicate is a shared function rather than a string
copied around.

Clock skew across API replicas is not a concern: `now()` is evaluated by
Postgres, so there is exactly one clock.

## Alternatives rejected

- **Redis as truth, Postgres as a mirror.** Fastest, and wrong for the reasons
  above.
- **Redis keyspace notifications driving a release worker.** Notifications are
  fire-and-forget; a missed message strands a seat indefinitely.
- **A dedicated `holds` table.** Cleaner-looking, but it puts hold state and
  seat state in two rows that must be kept in sync — reintroducing, inside one
  database, the split brain this ADR exists to avoid.
