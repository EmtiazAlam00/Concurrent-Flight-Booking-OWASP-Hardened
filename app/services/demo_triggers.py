"""Deterministic failure triggers for the demo/test payment path.

Every branch of the booking saga has to be reproducible on demand — in a live
demo, and in CI. Rather than sprinkling mocks around, the *last four characters
of the card token* select the behaviour, the way real gateways' test cards do.

This is the only place the mapping is defined; both the fake gateway and the
fake ticketing service read it, so a scenario can't drift between them.
"""

from enum import StrEnum


class Trigger(StrEnum):
    APPROVE = "approve"
    DECLINE_INSUFFICIENT_FUNDS = "decline_insufficient_funds"
    DECLINE_DO_NOT_HONOR = "decline_do_not_honor"
    TICKETING_FAILURE = "ticketing_failure"
    GATEWAY_TIMEOUT_THEN_OK = "gateway_timeout_then_ok"
    REFUND_FAILURE = "refund_failure"


#: suffix -> behaviour. Documented in README under "Demo card tokens".
SUFFIX_TRIGGERS: dict[str, Trigger] = {
    "0000": Trigger.APPROVE,
    "0002": Trigger.DECLINE_INSUFFICIENT_FUNDS,
    "0069": Trigger.DECLINE_DO_NOT_HONOR,
    "9995": Trigger.TICKETING_FAILURE,
    "0119": Trigger.GATEWAY_TIMEOUT_THEN_OK,
    "5309": Trigger.REFUND_FAILURE,
}

DECLINE_CODES = {
    Trigger.DECLINE_INSUFFICIENT_FUNDS: "insufficient_funds",
    Trigger.DECLINE_DO_NOT_HONOR: "do_not_honor",
}


def trigger_for(card_token: str) -> Trigger:
    return SUFFIX_TRIGGERS.get(card_token[-4:], Trigger.APPROVE)
