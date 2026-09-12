# Failure matrix

Every way the booking saga can fail, what the caller sees, what mechanism
produces that outcome, and the test that proves it.

This table is the answer to "what happens when step 3 of 4 fails?". Each row is
executable: the *Test* column names a real test, and the demo card tokens make
every branch reproducible by hand in Swagger.

## The saga

```
PENDING ──charge ok──> PAYMENT_AUTHORIZED ──tickets ok──> TICKETED ──> CONFIRMED
   │                          │
   │ charge declined          │ ticketing failed
   ▼                          ▼
PAYMENT_FAILED          COMPENSATING ──void/refund ok──> VOIDED
(seats stay held)                    └─reversal failed─> NEEDS_MANUAL_REVIEW
```

## The matrix

| # | Failure | Caller sees | What the system does | Mechanism | Test |
|---|---|---|---|---|---|
| 1 | Two users hold the same seat at once | one `201`, one `409 seat_unavailable` | winner holds; loser told immediately | single conditional `UPDATE`; zero rows = lost the race (`app/services/holds.py`) | `test_twenty_racers_one_seat_exactly_one_winner` |
| 2 | Hold expired before checkout | `409 hold_expired` | **no booking, no charge** | holds re-verified under `FOR UPDATE` as step 0 of the saga | `TestMatrixRow2HoldExpiredBeforePayment` |
| 3 | Hold expires *during* payment | `201` if the seat was still free, else `409 booking_compensated` | seat reclaimed, or charge reversed | seats re-locked and re-checked after the gateway call | `_issue_tickets` re-verification; `test_the_seat_is_immediately_bookable_again` |
| 4 | Card declined | `402 payment_declined` | booking `PAYMENT_FAILED`; **hold left intact** so the customer can retry with another card | nothing succeeded, so nothing to compensate | `test_402_and_hold_survives_for_a_retry` |
| 5 | Charge succeeds, ticketing fails | `409 booking_compensated` | authorization voided, seat released, booking `VOIDED` | compensating transaction | `test_compensates_and_releases_the_seat` |
| 6 | Gateway times out (outcome unknown) | `201` | retried with the **same** gateway idempotency key; charged exactly once | gateway-level idempotency; `PAYMENT_UNKNOWN` journalled first | `test_retried_with_the_same_key_and_charged_once` |
| 7 | Compensation itself fails | `409 booking_compensated` | booking `NEEDS_MANUAL_REVIEW`, seat still released, `CRITICAL` security event | explicit terminal state — not swallowed | `test_lands_in_needs_manual_review` |
| 8 | Client retries an identical request | original status and body, `Idempotency-Replayed: true` | one booking, one ticket, one charge | idempotency record replay | `test_identical_retry_replays_the_same_booking` |
| 9 | Same key, **different** body | `422 idempotency_key_reused` | nothing runs | request-hash comparison | `test_same_key_different_body_is_422` |
| 10 | Retry of a *declined* booking | `402` again | not re-charged | failures are recorded against the key too | `test_a_declined_attempt_replays_as_declined` |
| 11 | Sweep runs mid-checkout | unaffected `201` | sweep releases nothing | sweep's `UPDATE` is conditional on still-expired **and** `booking_id IS NULL`; it blocks on the saga's row lock | `test_sweep_cannot_steal_a_seat_mid_checkout` |
| 12 | Two multi-seat bookings, overlapping seats, opposite order | clean `404` each | no deadlock | seats locked in primary-key order | `test_concurrent_multi_seat_bookings_do_not_deadlock` |
| 13 | User B requests user A's booking | `404 not_found` | `AUTHZ_DENIED` security event | ownership is in the `WHERE` clause | `test_every_booking_scoped_route_is_ownership_checked` |
| 14 | Rotated refresh token replayed | `401 token_reuse_detected` | entire token family revoked, `HIGH` event | `used_at` sentinel | `test_replaying_a_rotated_token_kills_the_whole_family` |
| 15 | Card-testing pattern detected | `403 payment_blocked` | gateway never called | velocity rules scored before authorization | `test_a_blocked_payment_never_reaches_the_gateway` |
| 16 | Booking someone else's hold | `404 not_found` | nothing | hold lookup filtered by `held_by_user_id` | `test_cannot_book_someone_elses_hold` |
| 17 | Redis unavailable | booking succeeds | rate limiting and fraud detection degrade, loudly logged | derived state only; fails open by design | `test_a_broken_limiter_does_not_break_the_api`, `test_detection_failing_open_does_not_break_booking` |
| 18 | Booking cancelled, then the seat resold | second booking `201` | old ticket voided, seat genuinely resellable | tickets are voided not deleted; unique index is partial on `voided_at IS NULL` | `test_a_cancelled_seat_can_be_sold_again` |
| 19 | Oversell attempt under load | ≤ capacity confirmed, rest `409` | never oversells | row-level locking end to end | `load/oversell_proof.py`, `test_full_pipeline_never_oversells` |

## Reproducing each branch by hand

The last four characters of the card token select the gateway's behaviour, the
way real gateways' test cards do. Any prefix matching `tok_test_[A-Za-z0-9]{8,}`
works.

| Token | Behaviour | Exercises |
|---|---|---|
| `tok_test_aaaa11110000` | approved | happy path |
| `tok_test_aaaa11110002` | declined — insufficient funds | row 4 |
| `tok_test_aaaa11110069` | declined — do not honor | row 4 |
| `tok_test_aaaa11119995` | authorized, then ticketing fails | row 5 |
| `tok_test_aaaa11110119` | gateway times out, succeeds on retry | row 6 |
| `tok_test_aaaa11115309` | compensation fails | row 7 |

Defined in one place: `app/services/demo_triggers.py`.

## What is *not* handled

Stated plainly, because a matrix that claims completeness it doesn't have is
worse than one that admits its edges:

- **Crash between the gateway call and the database write.** The idempotency
  record stays `IN_PROGRESS` and the retry gets `409 request_in_flight` until it
  expires. Recovering automatically needs a reconciliation job that re-queries
  the provider — designed, not built (see `SECURITY.md`, future work).
- **Partial multi-seat booking.** All seats succeed or none do; there is no
  "book the two seats we could get". That is a product decision, not a
  limitation, but it is a decision.
- **Refund timing.** The fake gateway refunds instantly. A real provider's
  refunds settle asynchronously, so `CANCELLED` would need to mean "refund
  initiated" with a webhook to confirm it.
