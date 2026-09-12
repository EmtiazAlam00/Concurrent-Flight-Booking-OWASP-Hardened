# ADR-0003 — Short transactions, a state machine, and compensation that can fail

**Status:** accepted · **Date:** 2026-09-10

## Context

A booking is hold → charge → issue tickets → confirm. The charge is a network
call to a system we do not control, so this cannot be one database transaction.
Any step can fail after the previous one succeeded, which means some failures
leave money moved and no ticket issued.

## Decision

**Several short transactions, not one long one.** Each step commits its own
transaction. A database transaction is *never* held open across the call to the
payment gateway — doing so would pin row locks for the duration of somebody
else's outage, and one slow provider would stall every booking on the flight.

**The audit log is the saga journal.** Each state change writes its
`booking_audit` row in the *same* transaction as the change. The log therefore
cannot claim something happened that rolled back, and a crash mid-saga leaves a
readable trail instead of ambiguity. `seq` is gap-free per booking; a gap means
a lost write, which is why tests assert on it.

(Security events are the mirror image — written in their *own* transaction, via
`session_scope()`, so that recording "we denied you" survives the rollback of
the thing being denied.)

**Re-verify after every gap.** Between the charge and ticketing there is a
window in which a hold can lapse. The saga re-takes the row locks and re-checks
rather than trusting what it read before the network call.

**Compensation is a real step that can itself fail.** Reversing a charge is a
second operation against the same unreliable system. When it fails the booking
goes to `NEEDS_MANUAL_REVIEW`, a `CRITICAL` security event is emitted, and the
dashboard surfaces it. The seat is still released — the customer should not lose
the seat *and* the money while an operator sorts it out.

**Every transition is validated.** `ALLOWED_TRANSITIONS` defines the state
machine, and `assert_can_transition` raises `IllegalTransition` on anything else.
That is deliberately distinct from `InvalidStateTransition`, which is the `409`
telling a caller their request doesn't fit the booking's current state. One is a
bug; the other is a normal answer.

## The states

```
PENDING ──charge ok──> PAYMENT_AUTHORIZED ──tickets ok──> TICKETED ──> CONFIRMED
   │                          │
   │ declined                 │ ticketing failed
   ▼                          ▼
PAYMENT_FAILED          COMPENSATING ──reversal ok──> VOIDED
(seats stay held)                    └─reversal failed─> NEEDS_MANUAL_REVIEW
```

`PAYMENT_FAILED` deliberately leaves the seat hold intact: nothing succeeded, so
there is nothing to unwind, and the customer should be able to retry with
another card inside their remaining TTL. Releasing the seat there would be
hostile and would hand it to someone else while the customer reaches for a
second card.

## Why not a saga framework, or an outbox

Temporal, Camunda, or a transactional outbox with a worker would all work and
are the right answer at scale. They are the wrong answer here: this saga has
four steps, one external call, and one process. A framework would add a
dependency, an operational surface, and a layer of indirection between the
reader and the actual reasoning — which is the thing worth showing. The audit
table already provides the journal a durable-execution engine would give.

The honest limitation is stated in the failure matrix: a crash between the
gateway call and the database write leaves the idempotency record `IN_PROGRESS`,
and recovering automatically needs a reconciliation job that re-queries the
provider. Designed, not built.

## Consequences

**Good.** No lock is held across a network call. Every partial state has a name,
so "what happened to booking K7R2MQ?" is answerable from one table. Every branch
is reachable on demand through the demo card tokens, so the failure matrix is
executable rather than aspirational.

**Costs.** More code than a single transaction, and more states than a
happy-path implementation would have. `NEEDS_MANUAL_REVIEW` implies an operator
workflow that does not exist yet beyond surfacing on the dashboard. And short
transactions mean the saga can be interrupted between them — which is precisely
why the re-verification and the idempotency table (ADR-0004) exist.
