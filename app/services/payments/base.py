from dataclasses import dataclass
from decimal import Decimal
from typing import Protocol


@dataclass(frozen=True)
class AuthorizationResult:
    provider_ref: str
    approved: bool
    failure_code: str | None = None
    message: str | None = None


class PaymentTimeout(Exception):
    """The gateway did not answer.

    Critically different from a decline: a decline is a *known* outcome, while a
    timeout means the charge may or may not have happened. The saga must retry
    with the same idempotency key rather than assume either way.
    """


class RefundFailed(Exception):
    """Compensation itself failed. The booking goes to NEEDS_MANUAL_REVIEW."""


class PaymentGateway(Protocol):
    name: str

    async def authorize(
        self,
        *,
        card_token: str,
        amount: Decimal,
        currency: str,
        idempotency_key: str,
        metadata: dict[str, str] | None = None,
    ) -> AuthorizationResult: ...

    async def capture(self, *, provider_ref: str, idempotency_key: str) -> AuthorizationResult: ...

    async def void(self, *, provider_ref: str, idempotency_key: str) -> None: ...

    async def refund(self, *, provider_ref: str, amount: Decimal, idempotency_key: str) -> None: ...
