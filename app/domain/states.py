from app.domain.enums import ALLOWED_TRANSITIONS, BookingState
from app.errors import InvalidStateTransition


class IllegalTransition(Exception):
    """Raised for a transition that the state machine does not define.

    This is a programming error, not a user error — it means the saga tried to
    move a booking somewhere the diagram has no arrow for. It is deliberately
    distinct from InvalidStateTransition, which is a 409 telling a caller that
    *their* request doesn't fit the booking's current state.
    """


def assert_can_transition(current: str, target: BookingState) -> None:
    allowed = ALLOWED_TRANSITIONS.get(BookingState(current), frozenset())
    if target not in allowed:
        raise IllegalTransition(
            f"{current} -> {target} is not a legal transition "
            f"(legal: {sorted(a.value for a in allowed) or 'none, terminal state'})"
        )


def require_state(current: str, *expected: BookingState) -> None:
    """Guard for caller-facing operations, e.g. cancelling a booking."""
    if BookingState(current) not in expected:
        raise InvalidStateTransition(
            f"Booking is {current}; this operation requires "
            f"{' or '.join(e.value for e in expected)}"
        )
