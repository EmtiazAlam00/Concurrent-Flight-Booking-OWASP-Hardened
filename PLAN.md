# SkyLock — Build Plan

Engineering plan for the secure flight booking API. The spec says *what* to build; this says
*how*, locks the design decisions that are easy to get wrong, and orders the work so every
milestone is demoable.

**Assumptions** (change these and the plan shifts): Python 3.12 + FastAPI + Postgres + Redis,
Jinja2/HTMX dashboard, solo build, no hard deadline — milestones are sized in effort, not dates.

---

## 1. Decisions to lock before writing code

These are the choices that are painful to reverse. Each one is also an interview answer.

### D1. Postgres is the source of truth for seat holds. Redis is not.

The spec says "Redis TTL keys" for hold expiry. **Don't make Redis authoritative.** A Redis key
that disappears on its own, while Postgres still says `status='held'`, is a split-brain: two
systems disagree about who owns seat 14C and neither is wrong. Redis evictions, restarts without
persistence, and failovers all produce this.

Instead:

- `seat_inventory` row carries `status`, `held_by_user_id`, `hold_expires_at`. That is the truth.
- **Expiry is evaluated lazily on read/write.** Every query that asks "is this seat takeable?"
  includes `(status = 'available' OR (status = 'held' AND hold_expires_at < now()))`. An expired
  hold is *already* not a hold, whether or not anything has cleaned it up.
- The background sweep is a **janitor, not the mechanism** — it normalizes rows back to
  `available` so the dashboard and queries stay tidy. If the sweep dies for an hour, correctness
  is unaffected. That's the property you want to be able to state out loud.
- Redis keeps derived/ephemeral state only: rate-limit counters, carding velocity windows,
  a hold-countdown cache for the dashboard. Losing Redis degrades features, never corrupts bookings.

### D2. Pessimistic locking, with a conditional UPDATE for the hot path

Two different shapes, both needed:

- **Acquiring a hold** — single atomic conditional UPDATE, no explicit `SELECT ... FOR UPDATE`:

  ```sql
  UPDATE seat_inventory
     SET status = 'held',
         held_by_user_id = :user_id,
         hold_expires_at = now() + :ttl,
         version = version + 1
   WHERE flight_id = :flight_id
     AND seat_no  = :seat_no
     AND (status = 'available'
          OR (status = 'held' AND hold_expires_at < now()))
  RETURNING id, hold_expires_at;
  ```

  `UPDATE` takes the row lock itself; the loser blocks, re-evaluates the `WHERE` against the
  committed row, matches nothing, and gets `0 rows` → `409 SEAT_UNAVAILABLE`. One round trip,
  no race window.

- **Confirming a booking** — explicit `SELECT ... FOR UPDATE` inside the transaction, because the
  saga reads several rows and applies business logic in Python before deciding. **Lock in a
  deterministic order** (sort seat ids ascending) so multi-seat bookings can't deadlock against
  each other.

Keep the `version` column even though the MVP is pessimistic: it costs nothing and lets you say
"here's the optimistic path, and here's why I didn't need a retry loop for a single contended row."

### D3. The saga is a state machine on the booking row

```
PENDING ──charge ok──> PAYMENT_AUTHORIZED ──issue ok──> TICKETED ──> CONFIRMED
   │                          │
   │ charge fail              │ issue fail
   ▼                          ▼
PAYMENT_FAILED          COMPENSATING ──void/refund ok──> VOIDED
                                     └─refund fail────> NEEDS_MANUAL_REVIEW
```

No distributed-transaction framework. Each step commits its own short transaction and writes an
audit row in the same transaction — so the audit log *is* the saga journal, and a crash leaves a
readable trail rather than ambiguity. `NEEDS_MANUAL_REVIEW` is deliberate: it's more honest than
pretending compensation can't fail, and it gives the dashboard something real to show.

### D4. Idempotency is a table, not a cache

```
idempotency_keys(
  key, user_id, endpoint, request_hash,
  state,            -- IN_PROGRESS | COMPLETED
  response_status, response_body jsonb, booking_id,
  created_at, expires_at,
  PRIMARY KEY (key, user_id)
)
```

Flow: `INSERT ... ON CONFLICT DO NOTHING`. Zero rows inserted means a duplicate →

- `COMPLETED` + same `request_hash` → replay the stored response verbatim (same status code).
- `IN_PROGRESS` → `409 REQUEST_IN_FLIGHT` with `Retry-After`. Do not run the saga twice.
- same key, **different** `request_hash` → `422 IDEMPOTENCY_KEY_REUSED`. This check is the one
  most implementations skip, and it's the one that catches a real client bug.

Pass your own idempotency key down to the (fake) payment gateway too — that's what makes
"retry after a timeout" safe end to end.

### D5. Ownership is enforced by the data access layer, not by `if` statements

One FastAPI dependency, used by every booking-scoped route:

```python
async def owned_booking(booking_ref: str, user: CurrentUser, db: Session) -> Booking:
    # ownership is in the WHERE clause — there is no "fetch then check" window
    b = await db.scalar(
        select(Booking).where(Booking.ref == booking_ref, Booking.user_id == user.id)
    )
    if b is None:
        raise NotFound()  # 404, never 403 — don't confirm the ID exists
    return b
```

Route handlers never receive a raw `booking_ref`, so a forgotten check is a *type error*, not a
silent vulnerability. `404` rather than `403` so the endpoint isn't an existence oracle.

### D6. The vulnerable version lives in git history, not behind a runtime flag

The spec wants you to build the BOLA-vulnerable version and demo the attack. Do it as a branch /
tag (`demo/bola-vulnerable`) plus a test that exploits it, and reference both from `SECURITY.md`.
Do **not** ship a `INSECURE_MODE=true` switch in `main` — a flag that disables authorization is
itself the finding, and "I can turn off authz with an env var" is the wrong impression to leave.

### D7. Money

`NUMERIC(12,2)` in Postgres, `Decimal` in Python, explicit ISO-4217 `currency` column on every
monetary row. Pydantic schemas serialize as a string, never a float. One shared `Money` value
object so rounding lives in exactly one place.

---

## 2. Schema sketch

```
users(id, email unique, password_hash, status, mfa_secret_enc NULL,
      failed_login_count, locked_until, created_at)

-- reference data (seeded, read-only)
airports(iata PK, icao, name, city, country, lat, lon, tz)
airlines(iata, icao, name, country, active)
routes(id, airline_iata, src_iata, dst_iata, equipment)

-- generated inventory
flights(id, flight_no, airline_iata, src_iata, dst_iata,
        depart_at timestamptz, arrive_at timestamptz,
        aircraft_type, base_fare numeric(12,2), currency,
        UNIQUE(airline_iata, flight_no, depart_at))
fare_classes(id, flight_id, code, cabin, multiplier, seats_total)
seat_inventory(id, flight_id, seat_no, cabin, fare_class_id,
               status,              -- available | held | booked
               held_by_user_id NULL, hold_id NULL, hold_expires_at NULL,
               booking_id NULL, version int NOT NULL DEFAULT 0,
               UNIQUE(flight_id, seat_no))

bookings(id, ref unique,           -- PNR, 6 chars, Crockford-ish alphabet
         user_id, flight_id, state, total_amount numeric(12,2), currency,
         idempotency_key, created_at, updated_at)
booking_passengers(id, booking_id, given_name, family_name,
                   dob_enc, passport_enc,     -- bytea, encrypted later (future work)
                   dob_hash, passport_last4)
payments(id, booking_id, provider_ref, card_token, card_fingerprint,
         amount, currency, state, failure_code, idempotency_key, created_at)
tickets(id, booking_id, passenger_id, seat_inventory_id, e_ticket_no, issued_at)

-- append-only
booking_audit(id bigserial, booking_id, seq, event_type, actor_type, actor_id,
              from_state, to_state, detail jsonb, occurred_at)
security_events(id bigserial, occurred_at, event_type, severity,
                actor_user_id NULL, ip inet, user_agent,
                resource_type, resource_id, decision, detail jsonb)

refresh_tokens(id, family_id, user_id, token_hash unique, parent_id NULL,
               issued_at, used_at NULL, revoked_at NULL, revoked_reason, expires_at)
idempotency_keys(...)   -- see D4
```

**Make the audit log actually immutable** — don't just promise not to write updates:

```sql
CREATE RULE booking_audit_no_update AS ON UPDATE TO booking_audit DO INSTEAD NOTHING;
CREATE RULE booking_audit_no_delete AS ON DELETE TO booking_audit DO INSTEAD NOTHING;
-- and, from a migration run as owner:
REVOKE UPDATE, DELETE ON booking_audit, security_events FROM skylock_app;
```

A `BEFORE UPDATE` trigger that `RAISE EXCEPTION`s is the louder alternative — either is worth far
more than a comment saying "append only". Test it: a test that asserts `UPDATE` fails.

Indexes that matter: `flights(src_iata, dst_iata, depart_at)`,
`seat_inventory(flight_id, status)`, partial index on `seat_inventory(hold_expires_at)
WHERE status='held'` for the sweep, `security_events(occurred_at DESC)`,
`booking_audit(booking_id, seq)`.

---

## 3. API surface

```
POST   /auth/register
POST   /auth/login                 -> access + refresh (refresh in httpOnly cookie or body)
POST   /auth/refresh               -> rotate; reuse => revoke family
POST   /auth/logout                -> revoke family
GET    /me

GET    /flights/search?origin&destination&date&cabin&page&page_size
GET    /flights/{id}
GET    /flights/{id}/seats         -> seat map with availability (expired holds read as free)

POST   /holds                      {flight_id, seat_no}  -> 201 {hold_id, expires_at} | 409
GET    /holds/{id}
DELETE /holds/{id}                 -> release early

POST   /bookings                   Idempotency-Key required; runs the saga
GET    /bookings                   -> caller's bookings only, paginated
GET    /bookings/{ref}             -> owned_booking dependency
PATCH  /bookings/{ref}             -> passenger detail changes only
POST   /bookings/{ref}/cancel      -> refund + release + audit

GET    /admin/security-events      admin scope; paginated, filterable
GET    /dash/...                   Jinja2 read-only views (audit, holds, security feed)
```

Conventions: RFC 9457 `application/problem+json` errors with a stable machine `code`; cursor
pagination on anything append-only (audit, events), offset pagination on search; `Idempotency-Key`
required on `POST /bookings` and honored on `POST /bookings/{ref}/cancel`.

---

## 4. The failure matrix

This table is the single most valuable artifact in the repo. Every row gets a test.

| # | Failure | Observable result | Mechanism |
|---|---|---|---|
| 1 | Two users hold the same seat simultaneously | exactly one `201`, other `409` | conditional UPDATE (D2) |
| 2 | Hold TTL expires before payment starts | `409 HOLD_EXPIRED`, **no charge** | hold re-verified under `FOR UPDATE` as step 0 of the saga |
| 3 | Hold expires *during* payment | charge already authorized → seat re-locked if still free; else auto-void + `409` | seat locked for the whole saga tx; compensation path |
| 4 | Card declined | `402`, booking `PAYMENT_FAILED`, hold **kept** until TTL so user can retry | no compensation needed; velocity counters incremented |
| 5 | Charge succeeds, ticketing fails | void/refund, seat released, booking `VOIDED`, 2 audit rows | compensating transaction |
| 6 | Charge succeeds, process crashes before recording | retry with same key replays or resumes; gateway idem key prevents double charge | `IN_PROGRESS` row + reconciliation pass |
| 7 | Compensation itself fails | booking `NEEDS_MANUAL_REVIEW`, surfaced on dashboard | explicit terminal state |
| 8 | Client retries identical request | same status + same body, one booking | idempotency replay |
| 9 | Same idem key, different payload | `422 IDEMPOTENCY_KEY_REUSED` | request hash compare |
| 10 | Sweep runs mid-confirm | sweep cannot steal the seat | sweep's UPDATE is conditional on `status='held' AND hold_expires_at < now()` and blocks on the saga's row lock |
| 11 | User B requests user A's booking | `404`, `authz_denied` security event | `owned_booking` dependency |
| 12 | Rotated refresh token replayed | `401`, entire family revoked, security event | `used_at` sentinel |
| 13 | Oversell attempt under load | seats booked ≤ seats available, always | k6 run asserting invariant |

---

## 5. Fake payment gateway

Build `FakePaymentGateway` with deterministic behavior driven by the card token suffix, so every
branch above is reproducible in a demo and in CI:

| token suffix | behavior |
|---|---|
| `...0000` | approve |
| `...0002` | decline (insufficient funds) |
| `...0069` | decline (do not honor) |
| `...9995` | approve auth, then fail ticketing (exercises compensation) |
| `...0119` | timeout — no response, then succeed on retry with same idem key |
| `...refundfail` | compensation failure → `NEEDS_MANUAL_REVIEW` |

Interface is `authorize / capture / void / refund`, all taking an idempotency key. Swapping in
Stripe test mode later is then a one-class change — which is exactly the "future work" claim you
want to be able to back up.

---

## 6. Security work, concretely

**Auth.** Argon2id (`argon2-cffi`, tuned to ~100ms). Access JWT ~10 min, `kid` in the header so
keys can rotate; refresh ~14 days, stored only as a SHA-256 hash. Login lockout: exponential
backoff per (email, IP), `locked_until` on the user row, and a *constant-time-ish* response so
login isn't a user-enumeration oracle.

**Refresh reuse detection.** Tokens form a family (`family_id`). Rotation marks the parent
`used_at` and issues a child. Presenting a token whose `used_at` is set means either theft or a
buggy client — revoke the entire family, emit `REFRESH_REUSE_DETECTED` at `high`, force re-login.
Test both the happy rotation chain and the replay.

**BOLA.** `owned_booking` everywhere (D5), plus a **parametrized authorization matrix test** that
enumerates every booking-scoped route × {owner, other user, anonymous, admin} and asserts the
expected status. Drive the route list from `app.routes` so a newly added endpoint that forgets the
dependency *fails the test suite on day one*. That test is more impressive than the fix.

**Carding detection.** Sliding windows in Redis, keyed independently by `user_id`, `ip`, and
`card_fingerprint`. Rules, each with its own score:

1. ≥ 4 distinct card fingerprints on one account within 1h
2. ≥ 5 declines per account or IP within 10 min
3. decline burst (≥3) followed by an approval within 15 min — the classic "card validated" signal
4. ≥ 3 bookings per account within 2 min (rapid-fire)
5. one card fingerprint across ≥ 3 accounts within 24h

Score bands → `allow` / `challenge` (require re-auth or step-up) / `block` (`429`/`403`). Every
evaluation writes a `security_events` row with the rule hits in `detail`, so the dashboard can
show *why* something tripped. Ship a `scripts/simulate_carding.py` that drives a realistic attack
so the live feed lighting up is a one-command demo.

**Rate limiting.** Redis sliding window, per-IP and per-user, with tight buckets on
`/auth/login`, `/auth/refresh`, `/bookings`, `/holds`. Always return `429` + `Retry-After`, and
log the denial.

**Input validation.** Pydantic v2 with `model_config = ConfigDict(extra='forbid')` globally,
constrained types on every field (IATA codes as 3-char patterns, dates bounded to a sane window,
page size capped), and parameterized SQL only — no f-string query building anywhere, enforced by
a ruff/bandit rule in CI.

**`SECURITY.md`.** Assets → threats → mitigations → residual risk, one table per asset (PII,
payment data, loyalty points, seat inventory, auth tokens). Link each mitigation to the file and
test that implements it. Include the BOLA demo writeup and a short "what I'd do next" section.

---

## 7. Seeding

Two scripts, both idempotent and re-runnable:

1. `seed_reference.py` — download OurAirports `airports.csv` and OpenFlights
   `airlines.dat` / `routes.dat` into `data/` (cached, checksummed), then bulk-load via
   `COPY FROM STDIN`. Filter to scheduled-passenger airports with IATA codes to keep it sane.
2. `seed_flights.py --scale {demo,small,full} --days 14` — generate flight instances on real
   routes, then seat maps per aircraft type from templates (`A320` → 180 seats 30×6, `B738` → 189,
   `B77W` → 396 with cabins).

**Watch the row count.** 200 routes × 14 days × 180 seats ≈ 500k `seat_inventory` rows. Fine for
Postgres, slow if you insert them one at a time through the ORM. Use
`INSERT ... SELECT FROM generate_series` or `COPY`, and make `demo` scale ~20 routes / 3 days so
`docker compose up && make seed` finishes in seconds.

---

## 8. Testing

- **Unit** — saga state transitions, carding rules, money arithmetic, PNR generation, token rotation.
- **Integration** — real Postgres + Redis via testcontainers (or a compose service in CI). Never
  mock the database; the whole point is the locking behavior.
- **Concurrency** — `asyncio.gather` of N independent sessions (separate connections, one barrier)
  all racing for one seat; assert exactly one winner. Repeat for confirm-vs-sweep and
  cancel-vs-confirm.
- **Invariant tests** — after any scenario: booked seats ≤ total seats; no seat booked twice; every
  `CONFIRMED` booking has exactly one ticket per passenger; audit `seq` is gap-free per booking.
- **Load** — k6 scenario: 200 VUs, 50 seats, all hitting hold→book. Assert `sum(201) ≤ 50` and
  zero `5xx`. Save the output into the README; "here is the proof" beats "I handled concurrency".
- **Security** — the authz matrix test, the refresh-replay test, the audit-immutability test, the
  carding-simulation test, and the BOLA exploit test on the `demo/bola-vulnerable` branch.

CI (GitHub Actions): ruff → mypy → pytest (with pg + redis services) → `pip-audit` + `bandit`.
Security-flavored CI fits the project's theme and takes an afternoon.

---

## 9. Repo layout

```
skylock/
  app/
    main.py  config.py  db.py  redis.py  deps.py  errors.py
    domain/        models.py  states.py  money.py
    schemas/
    api/           auth.py  flights.py  holds.py  bookings.py  admin.py  dashboard.py
    services/      holds.py  booking_saga.py  payments/  tickets.py  audit.py
    security/      hashing.py  tokens.py  authz.py  ratelimit.py  carding.py  events.py
    jobs/          sweep_expired_holds.py
    templates/     dashboard/*.html
  alembic/
  scripts/         seed_reference.py  seed_flights.py  simulate_carding.py
  tests/           unit/  integration/  concurrency/  security/  load/ (k6)
  docker-compose.yml  Dockerfile  Makefile
  README.md  SECURITY.md  docs/ADR-0001..  docs/failure-matrix.md
```

---

## 10. Milestones

Each milestone ends in something you can show. Estimates are focused-hours for someone comfortable
with the stack; double them if you're learning a piece.

| # | Milestone | Effort | Proof it's done |
|---|---|---|---|
| M0 | compose: FastAPI + Postgres + Redis, `/health`, Makefile, CI skeleton | 3h | `docker compose up` → green health check in CI |
| M1 | models + Alembic migrations, audit immutability rules | 6h | `alembic upgrade head`; test proves `UPDATE booking_audit` fails |
| M2 | both seed scripts, `--scale demo` | 6h | SQL query: airlines departing YOW; seat map for a real A320 |
| M3 | auth: register/login/refresh rotation/reuse detection/lockout | 8h | replayed refresh token revokes the family (test + log line) |
| M4 | flight search + seat map, pagination, validation | 5h | Swagger: search YOW→YYZ, see availability |
| M5 | seat holds + lazy expiry + sweep job | 6h | hold a seat, watch TTL tick down, confirm auto-release |
| M6 | booking saga: idempotency, PNR, audit, fake gateway, compensation | 12h | every row of the failure matrix, reproducible via magic card tokens |
| M7 | concurrency hardening + k6 oversell proof | 6h | k6 output: 200 VUs, 50 seats, 50 bookings, 0 oversell |
| M8 | BOLA: vulnerable branch + exploit test → dependency + authz matrix | 6h | attack test red on `demo/bola-vulnerable`, green on `main` |
| M9 | carding detection + security event log + rate limiting | 8h | `simulate_carding.py` → events appear with rule explanations |
| M10 | dashboard: audit log, live holds, HTMX security feed | 8h | screen recording of an attack being flagged live |
| M11 | `SECURITY.md`, ADRs, README + architecture diagram, résumé bullet | 6h | a stranger can clone, `make up`, and hit the demo in 5 min |

≈80 focused hours. **If you need to cut:** M9 can ship with 2 rules instead of 5, M10 can be two
static tables instead of HTMX, M2 can seed 20 routes. **Don't cut** M6, M7, M8, or M11 — those four
*are* the portfolio value. M11 especially: an unreadable README makes the other 70 hours invisible.

---

## 11. Risks

| Risk | Mitigation |
|---|---|
| Scope creep (MFA, PII encryption, ML carding, live APIs) | they're in the spec's "future work" list — write them in `SECURITY.md` as designed-not-built, with the schema already shaped for them |
| Async SQLAlchemy + locking confusion | integration-test the locking behavior at M1/M5 before layering the saga on top |
| Seed step too slow to demo | `--scale demo` from the start, bulk `COPY`, not ORM inserts |
| Concurrency test that isn't actually concurrent | separate connections + an explicit barrier; assert the test *fails* if you remove the `WHERE` guard |
| Dashboard becoming a second place booking logic lives | it gets read-only DB access / read-only endpoints, and no POST routes at all |
| Polish left to last and never done | M11 is a milestone with hours attached, not a cleanup phase |

---

## 12. First three commits

1. `chore: compose skeleton` — FastAPI `/health`, Postgres, Redis, Makefile, Actions workflow.
2. `feat: core schema + append-only audit` — models, first migration, immutability test.
3. `docs: ADRs 1-4` — the decisions in §1, written down while the reasoning is fresh. Interviewers
   read these; they're the cheapest credibility in the whole repo.
