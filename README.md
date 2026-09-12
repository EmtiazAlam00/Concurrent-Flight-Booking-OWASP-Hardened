# Secure Flight Booking API

Airline seat booking under real concurrency, with security engineering as a
first-class concern.

Two users racing for the last seat is the same problem as a double-spend. A
booking that charges a card and then fails to issue a ticket has to put the
money back. And an endpoint that returns a booking by reference has to know
whose booking it is. This service is built around those three problems, and
every claim below has a test behind it.

```
FastAPI · PostgreSQL · Redis · SQLAlchemy 2.0 · Docker
146 tests · 0 dependencies on a paid API tier
```

---

## Quick start

```bash
cp .env.example .env
make up                                  # api + postgres + redis, migrations applied
make seed                                # real airports/airlines/routes, then generated flights
```

| | |
|---|---|
| **Swagger** | http://localhost:8000/docs |
| **Dashboard** | http://localhost:8000/dash — `dash` / `dash-dev-password` |
| **Health** | http://localhost:8000/health |

```bash
make demo-carding     # drives a card-testing attack; watch /dash/security
make test             # the full suite
```

---

## The three engineering stories

### 1. No overselling, ever

Acquiring a seat is a **single conditional `UPDATE`**, not a read followed by a
write:

```sql
UPDATE seat_inventory SET status = 'held', hold_expires_at = now() + :ttl, ...
 WHERE flight_id = :f AND seat_no = :s
   AND (status = 'available' OR (status = 'held' AND hold_expires_at < now()))
RETURNING *;
```

The `UPDATE` takes the row lock itself. Concurrent writers serialize on it; the
loser re-evaluates the `WHERE` against the winner's committed row, matches
nothing, and gets zero rows back. **Zero rows is the answer** — no race window,
no retry loop, one round trip. The booking saga uses explicit
`SELECT … FOR UPDATE` instead, because it reads several rows and decides in
Python; multi-seat bookings lock in primary-key order so they cannot deadlock.

Proof, not assertion:

```
$ python -m load.oversell_proof --seats 50 --racers 400

400 attempts in 4.44s  (90 req-pairs/s)
  201 @book        50
  409 @hold        146      ← lost the race for that seat
  409 @hold-cap    204      ← account already at its hold limit

  seats offered      50
  bookings confirmed 50

  ✓ never oversold        (booked <= capacity)
  ✓ no phantom bookings   (booked == confirmed)
  ✓ one live ticket per booked seat
  ✓ no server errors      (losing a race is a 409, not a 500)
```

Note what it asserts: `booked <= capacity`, not `== capacity`. Utilisation can
legitimately fall short — racers share a small account pool and each account may
hold only six seats at once — and conflating "never oversells" with "always
sells out" would make the test lie about which property it proves.

And the tests were checked against a mutant: removing the `takeable()` guard
turns "one winner from twenty racers" into twenty winners and fails four tests.
A concurrency test that still passes with the locking removed is testing
nothing.

→ [ADR-0002](docs/ADR-0002-locking-strategy.md)

### 2. Seat holds that expire correctly

The obvious implementation is a Redis key with a TTL. It is also wrong: Redis
drops the key, Postgres still says `held`, and two systems now disagree about
who owns seat 14C with no principled way to decide.

Here **Postgres owns hold state and expiry is evaluated lazily**, in the `WHERE`
clause of every query that asks whether a seat can be taken. An expired hold is
already not a hold. The background sweep only tidies rows so `status` means what
it says.

The consequence worth stating in an interview: **stop the sweep job and nothing
oversells, no booking breaks, no seat is wrongly blocked.** There's a test for
exactly that — it never calls the sweep at all.

→ [ADR-0001](docs/ADR-0001-postgres-owns-seat-holds.md)

### 3. A saga that survives being interrupted

`hold → charge → issue tickets → confirm`, as several short transactions. A
database transaction is never held open across the call to the payment gateway —
that would pin row locks for the length of somebody else's outage.

```
PENDING ──charge ok──> PAYMENT_AUTHORIZED ──tickets ok──> TICKETED ──> CONFIRMED
   │                          │
   │ declined                 │ ticketing failed
   ▼                          ▼
PAYMENT_FAILED          COMPENSATING ──reversal ok──> VOIDED
(seats stay held)                    └─reversal failed─> NEEDS_MANUAL_REVIEW
```

- **Idempotent** on `Idempotency-Key`, including on failures — a retried decline
  replays the `402` instead of charging again. Same key with a *different* body
  is a `422`, not a silent replay.
- **Compensating** — if ticketing fails after the charge, the authorization is
  voided and the seat released.
- **Compensation can fail too.** That's `NEEDS_MANUAL_REVIEW`, a real state on
  the dashboard, not an exception we pretend can't happen.
- **The audit log is the journal** — each state change writes its audit row in
  the same transaction, so the log can't claim something that rolled back.

→ [ADR-0003](docs/ADR-0003-saga-and-compensation.md) ·
[ADR-0004](docs/ADR-0004-idempotency.md) ·
**[the full failure matrix](docs/failure-matrix.md)**

---

## Drive every failure branch yourself

The last four characters of the card token select the gateway's behaviour, the
way real gateways' test cards do:

| Token | What happens |
|---|---|
| `tok_test_aaaa11110000` | approved |
| `tok_test_aaaa11110002` | declined — **your seat hold survives** so you can retry |
| `tok_test_aaaa11119995` | charge succeeds, ticketing fails → compensation |
| `tok_test_aaaa11110119` | gateway times out, then succeeds on retry — **one charge** |
| `tok_test_aaaa11115309` | compensation itself fails → `NEEDS_MANUAL_REVIEW` |

Every one is reachable from Swagger in about a minute, and each has a test.

---

## Security

Framed against the OWASP API Security Top 10, with a
**[threat model](SECURITY.md)** that names the code and the test behind every
mitigation — and a "not mitigated" section that's as long as it honestly needs
to be.

**Object-level authorization (OWASP API #1)** is the centrepiece. Ownership is a
`WHERE` clause inside a dependency, so handlers take an `OwnedBooking` and never
a raw reference — forgetting the check is a type error, not a silent leak. It
answers `404`, never `403`, so the endpoint can't be used to enumerate PNRs.

The test that matters more than the fix walks `app.routes`, finds every
booking-scoped endpoint, and asserts each returns `404` to another user and
`401` to an anonymous one. **A new endpoint that forgets the dependency fails CI
the day it's written.**

There's a working exploit you can run:

```bash
$ python -m scripts.exploit_bola      # exits 0 when the target is safe

   [ok  ] GET    K7R2MQ        -> 404    read the booking (PII)
   [ok  ] GET    audit         -> 404    read its full history
   [ok  ] PATCH  K7R2MQ        -> 404    rename the passenger
   [ok  ] POST   cancel        -> 404    cancel someone else's flight

   real-but-not-mine K7R2MQ -> 404
   nonexistent       ZZZZZZ -> 404
   Identical responses: no way to distinguish. Not an oracle.
```

Against the vulnerable version every one of those returns `200` — including
cancelling and refunding a stranger's flight.
**[docs/bola-demo.md](docs/bola-demo.md)** has the full transcript, the damage
and the fix. It's a branch rather than an `INSECURE_MODE` flag on `main`,
because a switch that turns off authorization is itself the finding.

→ [ADR-0005](docs/ADR-0005-object-level-authorization.md)

**Also:** refresh-token rotation with **reuse detection** (replay a rotated token
and the whole family is revoked); Argon2id with a constant-time no-such-user
path so login isn't an enumeration oracle; seven-rule card-testing detection
that blocks *before* the gateway is called; sliding-window rate limits; strict
Pydantic validation with `extra="forbid"`.

**The audit log is append-only at the database level** — a raising trigger plus
`REVOKE UPDATE, DELETE` from the application role. Not a convention, a property:

```
$ psql -U skylock_app -c "DELETE FROM security_events"
ERROR:  permission denied for table security_events

$ psql -U skylock_owner -c "DELETE FROM security_events"
ERROR:  Table security_events is append-only; DELETE is not permitted
HINT:   Correct history by appending a compensating row.
```

---

## Watch it happen

The dashboard exists because security work is invisible until something makes it
visible. It is strictly read-only — a test asserts the router defines no
non-`GET` route.

- **`/dash/holds`** — active holds counting down, refreshing every second. A
  hold hitting zero disappears at the same moment it stops blocking anyone.
- **`/dash/audit`** — the append-only trail, colour-coded by event.
- **`/dash/security`** — the live feed. Run `make demo-carding` beside it:

```
Phase 2 — one account works through a list of stolen cards
  card 1 (…0002) -> 402 payment_declined
  card 2 (…0002) -> 402 payment_declined
  card 3 (…0002) -> 402 payment_declined
  card 4 (…0002) -> 403 payment_blocked          ← 4 distinct cards (40)
  card 5 (…0002) -> 403 payment_blocked            + non-human pacing (25) = 65

Phase 3 — the attacker reaches a card that is actually live
  -> 403 payment_blocked
  It never reached the payment gateway, so the attacker learns nothing
  about whether that card is good — which is the entire point of card testing.
```

Every detection carries the rules it hit and the counts that tripped them. A
feed that says "blocked" and nothing else isn't a detection surface.

---

## Data

Real reference data, self-generated inventory, no paid tier anywhere.

- **[OurAirports](https://davidmegginson.github.io/ourairports-data/)** (public
  domain) and **[OpenFlights](https://openflights.org/data.html)** (ODbL) give
  3,244 airports, 986 airlines and 61,837 real routes. So real questions have
  real answers from the first seed:

  ```
  Sanity check — airlines departing YOW (Ottawa):
    Air Canada        19 routes
    WestJet            6 routes
    United Airlines    5 routes
  ```

- **Flights and seat maps are generated** on top of those routes — no free API
  provides bookable seat inventory, and self-generating it means the core never
  depends on anyone's rate limit. Durations and fares come from the real
  great-circle distance; four aircraft types have genuinely different cabins.

```bash
python -m scripts.seed_flights --scale demo  --days 7    # ~44k seats, ~3s
python -m scripts.seed_flights --scale small --days 14
```

---

## Testing

```
$ make test
146 passed in 19.02s
```

| Suite | What it covers |
|---|---|
| `tests/unit` | money (half-up, never float), the state machine, PNR alphabet, idempotency hashing, password hashing — **no datastores needed** |
| `tests/integration` | every row of the failure matrix, against a real Postgres |
| `tests/concurrency` | genuine races: 20 requests for 1 seat, full pipeline vs. capacity, sweep vs. checkout, deadlock avoidance |
| `tests/security` | the BOLA route matrix, refresh replay, lockout, enumeration, `alg=none`, all seven carding rules, rate limits |
| `load/` | the oversell proof, in Python and k6 |

Integration tests run against real Postgres and Redis. Nothing about the locking
behaviour this service exists to get right survives being mocked.

---

## Layout

```
app/
  domain/     models, enums, the state machine, money
  services/   holds · booking_saga · idempotency · audit · payments/
  security/   authz · tokens · hashing · carding · ratelimit · events
  api/        auth · flights · holds · bookings · admin · dashboard
  jobs/       the one background job: the hold sweep
docs/         5 ADRs + the failure matrix
scripts/      seed_reference · seed_flights · simulate_carding
```

Everything is request-driven **except one background job**: the sweep that
releases expired holds. It only ever undoes something an earlier request did,
and it isn't load-bearing.

---

## Deliberately out of scope

A customer-facing booking site, a real payment gateway, Kubernetes.

Honest "next things", with the schema already shaped for them: field-level PII
encryption (the biggest real gap — see [SECURITY.md](SECURITY.md) §4), TOTP MFA,
breached-password screening, a reconciliation job for the crash-mid-charge case,
and a live-status endpoint over OpenSky.

---

## Licence

Code MIT. Reference data belongs to OurAirports (public domain) and OpenFlights
(ODbL — fine for non-commercial use; commercial use needs a licence).
