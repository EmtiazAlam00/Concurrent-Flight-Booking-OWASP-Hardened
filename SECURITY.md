# SkyLock — threat model

A short, honest threat model: what is worth stealing, who would want it, what
stops them, and what doesn't. Every mitigation names the code that implements it
and the test that proves it, so nothing here is a claim you have to take on
trust.

Framed against the **OWASP API Security Top 10 (2023)**.

> **Scope.** This is a portfolio project. It is not deployed, not handling real
> cards, and not PCI-assessed. The "Not mitigated" section is as important as
> the rest — a threat model that only lists wins is marketing.

---

## 1. Assets

| Asset | Why an attacker wants it | Blast radius if lost |
|---|---|---|
| **Passenger PII** — names, DOB, passport numbers, itineraries | identity fraud; itineraries reveal when a home is empty | high, irreversible — you cannot reissue someone's passport number |
| **Payment data** — gateway card tokens, fingerprints | testing stolen cards; a booking flow is a cheap yes/no oracle | high — direct financial harm to third parties |
| **Seat inventory** | denial of inventory; scalping; oversell chaos | medium — revenue and operational |
| **Auth tokens** — access, refresh | full account takeover | high |
| **Loyalty balances** *(modelled, not implemented)* | points are stealable, fungible currency; the classic credential-stuffing target | high |
| **Audit + security logs** | an attacker's first instinct is to erase their trail | high — losing these means losing the ability to know what happened |

## 2. Trust boundaries

```
    internet
       │  ← untrusted: every field, header and path parameter
   ┌───▼──────────────────────────────────────────────┐
   │ FastAPI                                          │
   │   Pydantic strict validation (extra="forbid")    │
   │   AuthContextMiddleware  (identity, no authority)│
   │   rate limiting  →  authn  →  authz  →  handler  │
   └───┬───────────────────────────┬──────────────────┘
       │                           │
  ┌────▼─────┐              ┌──────▼──────┐      ┌──────────────┐
  │ Postgres │              │    Redis    │      │ payment gwy  │
  │  TRUTH   │              │  DERIVED    │      │  untrusted   │
  │ app role │              │ no persist. │      │  output      │
  │ can't    │              │ fails open  │      └──────────────┘
  │ UPDATE   │              └─────────────┘
  │ audit    │
  └──────────┘
```

Two boundaries are worth stating explicitly:

- **The app role is not trusted with history.** `skylock_app` has `UPDATE`,
  `DELETE` and `TRUNCATE` revoked on `booking_audit` and `security_events`.
  Application compromise does not imply log compromise.
- **`X-Forwarded-For` is not trusted.** This service does not know whether it
  sits behind a proxy it controls, and an attacker-supplied header would let
  anyone forge the identity that rate limits and velocity rules key on
  (`app/security/events.py::client_ip`). Behind a real load balancer you would
  terminate XFF there.

## 3. Threats and mitigations

### API1:2023 — Broken Object Level Authorization *(the centerpiece)*

| Threat | Mitigation | Code | Test |
|---|---|---|---|
| Read another user's booking by changing the PNR | ownership is a `WHERE` clause in a dependency; handlers never receive a raw ref | `app/security/authz.py` | `test_every_booking_scoped_route_is_ownership_checked` |
| Enumerate valid PNRs by status code | `404` for both unauthorized and nonexistent, byte-identical bodies | same | `test_someone_elses_booking_and_a_fake_one_are_indistinguishable` |
| Modify/cancel another user's booking | same dependency on every mutating route | `app/api/bookings.py` | route matrix (all 4 routes × 3 caller types) |
| Book against someone else's hold | hold lookup filtered by `held_by_user_id` | `booking_saga._lock_seats_for_holds` | `test_cannot_book_someone_elses_hold` |
| A *new* endpoint forgets the check | the matrix test discovers routes from `app.routes` — it fails on the new endpoint automatically | `tests/security/test_authz_matrix.py` | `test_the_route_inventory_is_not_empty` guards the guard |

`scripts/exploit_bola.py` runs the attack against a live server and exits
non-zero if it succeeds, so it doubles as a deployment smoke test. The vulnerable
variant, the full transcript of what it leaks, and the fix are in
**[docs/bola-demo.md](docs/bola-demo.md)**; reintroducing it on a
`demo/bola-vulnerable` branch takes one edit. Deliberately not a runtime flag on
`main` — see ADR-0005.

### API2:2023 — Broken Authentication

| Threat | Mitigation | Test |
|---|---|---|
| Offline cracking of a stolen dump | Argon2id, 64 MiB / t=3 / p=2 (~100 ms per verify) | `test_uses_argon2id` |
| Credential stuffing (loyalty accounts are prime targets) | per-account lockout after 5 failures + per-IP rate limit — neither a single-account brute force nor a spray gets unbounded guesses | `TestBruteForceLockout` |
| User enumeration via login | identical `401` and body; a dummy Argon2 verify burns equal CPU on the no-such-user path | `test_unknown_and_wrong_password_are_indistinguishable` |
| **Stolen refresh token** | rotation + reuse detection: replaying a rotated token revokes the entire family | `test_replaying_a_rotated_token_kills_the_whole_family` |
| Token forgery (`alg=none`) | algorithm pinned in `jwt.decode`; `iss`/`aud`/`exp` required | `test_the_none_algorithm_is_not_accepted` |
| Refresh token used as an access token | `typ` claim checked | `test_a_refresh_token_is_not_an_access_token` |
| Token outliving the account | every request re-checks the user exists and is active | `app/deps.py::current_user` |
| Database dump yields usable tokens | only SHA-256 of refresh tokens is stored | `app/security/tokens.py` |

**On reuse detection:** presenting an already-used refresh token means either
theft or a buggy client, and the two are indistinguishable. We assume theft and
kill the family. The legitimate user re-authenticates once; an attacker holding
a stolen token loses the session entirely. `test_the_user_can_still_log_in_again`
asserts the user is not permanently locked out.

### API3 / API4 — Property-level authorization and resource consumption

| Threat | Mitigation |
|---|---|
| Mass assignment via unexpected fields | `extra="forbid"` on every request model (`app/schemas/common.py`) — tested |
| Over-exposure of PII | responses return `passport_last4` only; the full number never appears in any response, asserted in the happy-path test |
| Price tampering | price is read from `seat_inventory`, never from the request |
| Unbounded pagination | page size capped at 100; search window capped at 365 days |
| Denial of inventory (hold squatting) | max 6 active holds per account; expired holds don't count |
| Request flooding | sliding-window rate limits, tightest on `/auth/*` and `/bookings` |

### API5 — Broken Function Level Authorization

Admin scope on `/admin/*`, checked against the database rather than the token
claim alone; denials logged. Tested for normal user (403), admin (200) and
anonymous (401).

### API6 — Unrestricted Access to Sensitive Business Flows *(card testing)*

Airlines are prime carding targets: high-value, instantly fungible, and the
authorize/void flow is a cheap yes/no oracle for a stolen card.

Seven rules score each attempt *before* the gateway is called
(`app/security/carding.py`):

| Rule | Signal | Score |
|---|---|---|
| `distinct_cards_per_account` | ≥4 different cards on one account in 1h | 40 |
| `card_across_accounts` | one card on ≥3 accounts in 24h | 45 |
| `declines_per_account` | ≥5 declines in 10m | 35 |
| `declines_per_ip` | ≥8 declines in 10m | 30 |
| `rapid_fire_bookings` | ≥3 attempts in 2m | 25 |
| `small_amount_velocity` | ≥5 low-value auths in 1h | 20 |
| `recent_card_validation` | a decline burst followed by a success | 50 |

≥60 blocks, ≥30 flags. Rules combine: four distinct cards (40) plus non-human
pacing (25) is 65, which is what stops the demo attack at card four — **before
any card is validated**, so the attacker learns nothing.

`recent_card_validation` is the interesting one: decline-decline-decline-approve
can only be recognised *after* the success, so instead of blocking a request
that already succeeded it raises a 30-minute risk flag that makes the account's
next attempt score on its own.

Every detection writes a `security_events` row carrying the rules hit and the
counts that tripped them — the difference between a log and a detection surface.
`make demo-carding` drives the full attack; watch `/dash/security`.

### API7 — Server Side Request Forgery

Not applicable: the service makes no outbound requests from user input. The
optional live-API enrichment endpoint is future work and would need an allowlist.

### API8 — Security Misconfiguration

Non-root container; least-privilege database role; secrets from environment;
`.env` gitignored; htmx vendored rather than loaded from a CDN (a security
dashboard should not hand a third-party origin the operator's session); the
dashboard exposes no write routes, asserted structurally by a test.

### API9 / API10 — Inventory and unsafe consumption

Full OpenAPI at `/docs`; the payment gateway is behind a protocol boundary and
its output is treated as untrusted.

### Injection

Parameterized queries only, via SQLAlchemy — no string-built SQL anywhere.
Constrained types at the edge do most of the work: IATA codes are
`^[A-Za-z]{3}$`, seat numbers `^[0-9]{1,3}[A-Za-z]$`, names reject digits and
symbols, card tokens must match `^tok_(test|live)_[A-Za-z0-9]{8,48}$` (so a real
PAN posted by mistake is a `422`, not a compliance incident). Rejections are
logged, without the offending value — it might be a credential.

> One finding from building this: `origin: IataCode = Query(...)` **silently
> discards** the `Field` constraints from the annotated type, because FastAPI
> takes the `Query` object as the parameter's metadata. The validation looked
> present and wasn't. Caught by a test that posts `XAA' OR 1=1--` and expects a
> `422`; fixed by putting the constraints inside a single `Annotated`
> (`app/schemas/flights.py::IataQuery`). Parameterized queries meant this was
> never exploitable — but the defense-in-depth layer was missing and silent,
> which is exactly the kind of gap that only a test finds.

### Auditability

| Threat | Mitigation |
|---|---|
| Attacker erases their trail | `booking_audit` and `security_events` are append-only **at the database level**: a `BEFORE UPDATE/DELETE/TRUNCATE` trigger that `RAISE`s (applies to every role, including the owner) *plus* `REVOKE` from the app role (migration `0002`) |
| Log claims something that rolled back | audit rows are written in the same transaction as the change they describe |
| A denial is lost when its transaction rolls back | security events are written in their own transaction |
| Silently dropped writes | `seq` is gap-free per booking, asserted in tests |

A `RULE … DO INSTEAD NOTHING` was rejected in favour of a raising trigger:
reporting success while discarding the statement is worse than either allowing
or refusing it.

## 4. Not mitigated — known gaps

Stated plainly. These are the honest answers to "what would you harden next?",
in rough priority order.

1. **PII is not encrypted at rest.** `dob_enc` / `passport_enc` are `bytea`
   columns holding encoded-but-not-encrypted values. The columns and the
   `passport_last4` split exist so envelope encryption (per-record DEK, KMS-held
   KEK) can be added without migrating live data — but today, database access
   means PII access. **This is the largest real gap.**
2. **No MFA.** `pyotp` and the `mfa_secret_enc` column are in place; the
   enrolment and challenge flows are not. Justified for a service holding PII
   and payment data.
3. **No breached-password screening.** The policy is a 12-character minimum and
   a token blocklist. A Have I Been Pwned k-anonymity range check would catch far
   more than composition rules ever do.
4. **No reconciliation job.** A crash between the gateway call and the database
   write strands an idempotency key as `IN_PROGRESS` until it expires. Recovery
   needs a worker that re-queries the provider.
5. **Rate limiting fails open.** A Redis outage disables it. Correct for login
   availability, arguably wrong for the payment bucket, where failing *closed*
   would be the better trade. Not yet split per bucket.
6. **Access tokens are not revocable before expiry.** A 10-minute TTL bounds the
   damage; a `jti` denylist in Redis would close it.
7. **Dashboard uses HTTP Basic.** Proportionate for a single-operator local
   tool, wrong for anything shared — it should sit behind the same SSO as the
   rest of an admin surface.
8. **Single HMAC signing key, no rotation.** The `kid` header is emitted but
   there is no key set to rotate through.
9. **No TLS termination in-repo, no CSP/HSTS headers.** Deployment concerns, but
   real ones.
10. **Carding thresholds are untuned.** They are reasoned, not fitted to data.
    Real deployment needs a false-positive rate measured against real traffic,
    and probably a model rather than fixed thresholds.

## 5. Reporting

This is a portfolio project with no production deployment. If you find something
interesting, open an issue — including in this threat model itself.
