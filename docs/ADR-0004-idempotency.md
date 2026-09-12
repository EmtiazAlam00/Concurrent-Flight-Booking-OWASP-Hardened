# ADR-0004 — Idempotency keys live in Postgres, and record failures too

**Status:** accepted · **Date:** 2026-09-10

## Context

A client whose connection drops mid-booking does not know whether the booking
happened. It will retry. Without a guarantee, that retry is a second charge.

## Decision

`POST /bookings` requires an `Idempotency-Key` header. Claims are rows in
Postgres (`idempotency_keys`), keyed by `(key, user_id)`, holding the SHA-256 of
the canonicalized request body, a state, and the stored response.

The claim is taken with `INSERT … ON CONFLICT DO NOTHING … RETURNING`, and
committed immediately so concurrent duplicates see `IN_PROGRESS` at once. Three
outcomes:

1. **Same key, same body, finished** → replay the stored response byte for byte,
   including the original status code, plus `Idempotency-Replayed: true`.
2. **Same key, same body, still running** → `409 request_in_flight` with
   `Retry-After`. Do not start the saga twice; that is exactly the double-charge
   being prevented.
3. **Same key, *different* body** → `422 idempotency_key_reused`.

**The third case is the one most implementations skip**, and skipping it is what
turns an idempotency key into a cache key. A client that reuses a key for a
genuinely different request has a bug; silently replaying the first response
hides it and books the wrong thing. Surfacing it costs one hash comparison.

**Failures are recorded too.** A retried booking that was declined replays the
`402` rather than attempting a second charge. Only *unexpected* exceptions
release the claim, because those are the cases where we cannot honestly describe
what happened and the client deserves a clean retry.

**The key is passed down to the gateway** as `{key}:auth`. That is what makes
the timeout path safe: the saga re-calls `authorize` with the same key, and the
gateway either performs the charge or replays its first one.

**Scoped per user.** Two customers may legitimately choose the same key. The
composite primary key means they never collide, and one user cannot probe
another's keyspace.

## Why not Redis

The guarantee has to survive a Redis restart. Redis is configured here with no
persistence at all (ADR-0001), because it holds only derived state — an
idempotency record is not derived state, it is the record of a financial
operation. Putting it in Redis would mean a cache eviction could cause a double
charge, which is the exact failure the mechanism exists to prevent.

The claim also has to be transactional with the booking it protects, and it is
useful to be able to join it against `bookings` when reconciling.

## Consequences

**Good.** A retry storm produces one booking and one charge. The `422` catches a
real class of client bug early. Records expire after 24h (`expires_at`), so the
table does not grow without bound, and an expired claim is cleared before a
fresh insert so a key can legitimately be reused later.

**Costs.** Two extra round trips on the booking path (claim, then complete), and
a table that needs periodic pruning — currently only pruned opportunistically on
collision, which is fine at this scale and would want a scheduled job at any
real volume. The `IN_PROGRESS` state can strand a key if the process dies at
exactly the wrong moment; the client then gets `409` until expiry rather than a
clean retry. That is the conservative failure and it is the right one, but it is
a rough edge, noted in the failure matrix.
