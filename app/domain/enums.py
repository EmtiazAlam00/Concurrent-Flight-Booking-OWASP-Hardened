from enum import StrEnum


class SeatStatus(StrEnum):
    AVAILABLE = "available"
    HELD = "held"
    BOOKED = "booked"


class BookingState(StrEnum):
    """The saga's state machine. See docs/failure-matrix.md.

    PENDING -> PAYMENT_AUTHORIZED -> TICKETED -> CONFIRMED
       |              |
       |              +-- ticketing failed --> COMPENSATING --> VOIDED
       |                                                   \\-> NEEDS_MANUAL_REVIEW
       +-- charge failed --> PAYMENT_FAILED
    """

    PENDING = "PENDING"
    PAYMENT_AUTHORIZED = "PAYMENT_AUTHORIZED"
    TICKETED = "TICKETED"
    CONFIRMED = "CONFIRMED"
    PAYMENT_FAILED = "PAYMENT_FAILED"
    COMPENSATING = "COMPENSATING"
    VOIDED = "VOIDED"
    CANCELLED = "CANCELLED"
    NEEDS_MANUAL_REVIEW = "NEEDS_MANUAL_REVIEW"


TERMINAL_BOOKING_STATES = frozenset(
    {
        BookingState.CONFIRMED,
        BookingState.PAYMENT_FAILED,
        BookingState.VOIDED,
        BookingState.CANCELLED,
        BookingState.NEEDS_MANUAL_REVIEW,
    }
)

#: Only these transitions are legal. Enforced in app/domain/states.py so an
#: illegal transition is a loud error, not a silently corrupt booking.
ALLOWED_TRANSITIONS: dict[BookingState, frozenset[BookingState]] = {
    BookingState.PENDING: frozenset(
        {BookingState.PAYMENT_AUTHORIZED, BookingState.PAYMENT_FAILED, BookingState.COMPENSATING}
    ),
    BookingState.PAYMENT_AUTHORIZED: frozenset({BookingState.TICKETED, BookingState.COMPENSATING}),
    BookingState.TICKETED: frozenset({BookingState.CONFIRMED, BookingState.COMPENSATING}),
    BookingState.CONFIRMED: frozenset({BookingState.CANCELLED}),
    BookingState.COMPENSATING: frozenset({BookingState.VOIDED, BookingState.NEEDS_MANUAL_REVIEW}),
    BookingState.PAYMENT_FAILED: frozenset(),
    BookingState.VOIDED: frozenset(),
    BookingState.CANCELLED: frozenset(),
    BookingState.NEEDS_MANUAL_REVIEW: frozenset({BookingState.VOIDED, BookingState.CANCELLED}),
}


class PaymentState(StrEnum):
    PENDING = "PENDING"
    AUTHORIZED = "AUTHORIZED"
    CAPTURED = "CAPTURED"
    DECLINED = "DECLINED"
    VOIDED = "VOIDED"
    REFUNDED = "REFUNDED"
    UNKNOWN = "UNKNOWN"  # gateway timed out; real state not yet established


class AuditEventType(StrEnum):
    BOOKING_CREATED = "BOOKING_CREATED"
    SEATS_LOCKED = "SEATS_LOCKED"
    PAYMENT_AUTHORIZED = "PAYMENT_AUTHORIZED"
    PAYMENT_DECLINED = "PAYMENT_DECLINED"
    PAYMENT_UNKNOWN = "PAYMENT_UNKNOWN"
    TICKETS_ISSUED = "TICKETS_ISSUED"
    TICKETING_FAILED = "TICKETING_FAILED"
    BOOKING_CONFIRMED = "BOOKING_CONFIRMED"
    COMPENSATION_STARTED = "COMPENSATION_STARTED"
    PAYMENT_VOIDED = "PAYMENT_VOIDED"
    PAYMENT_REFUNDED = "PAYMENT_REFUNDED"
    COMPENSATION_FAILED = "COMPENSATION_FAILED"
    SEATS_RELEASED = "SEATS_RELEASED"
    HOLD_LOST = "HOLD_LOST"
    BOOKING_CANCELLED = "BOOKING_CANCELLED"
    PASSENGER_UPDATED = "PASSENGER_UPDATED"


class SecurityEventType(StrEnum):
    LOGIN_SUCCEEDED = "LOGIN_SUCCEEDED"
    LOGIN_FAILED = "LOGIN_FAILED"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    REGISTERED = "REGISTERED"
    REFRESH_ROTATED = "REFRESH_ROTATED"
    REFRESH_REUSE_DETECTED = "REFRESH_REUSE_DETECTED"
    REFRESH_REJECTED = "REFRESH_REJECTED"
    AUTHZ_DENIED = "AUTHZ_DENIED"
    RATE_LIMITED = "RATE_LIMITED"
    CARDING_SUSPECTED = "CARDING_SUSPECTED"
    CARDING_BLOCKED = "CARDING_BLOCKED"
    PAYMENT_DECLINED = "PAYMENT_DECLINED"
    IDEMPOTENCY_KEY_REUSED = "IDEMPOTENCY_KEY_REUSED"
    VALIDATION_REJECTED = "VALIDATION_REJECTED"
    #: Not an attack — an operational alert. A booking is stuck holding
    #: someone's money and needs a human. It belongs on the same feed because
    #: that is the feed an operator actually watches.
    MANUAL_REVIEW_REQUIRED = "MANUAL_REVIEW_REQUIRED"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IdempotencyState(StrEnum):
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"


class Decision(StrEnum):
    ALLOW = "allow"
    CHALLENGE = "challenge"
    BLOCK = "block"
