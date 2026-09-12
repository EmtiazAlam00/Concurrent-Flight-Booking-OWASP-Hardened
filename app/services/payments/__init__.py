from functools import lru_cache

from app.config import settings
from app.services.payments.base import (
    AuthorizationResult,
    PaymentGateway,
    PaymentTimeout,
    RefundFailed,
)
from app.services.payments.fake import FakePaymentGateway

__all__ = [
    "AuthorizationResult",
    "PaymentGateway",
    "PaymentTimeout",
    "RefundFailed",
    "FakePaymentGateway",
    "get_gateway",
]


@lru_cache
def get_gateway() -> PaymentGateway:
    if settings.payment_provider == "fake":
        return FakePaymentGateway()
    raise RuntimeError(
        f"Unknown PAYMENT_PROVIDER {settings.payment_provider!r}. "
        "Real provider integration is documented future work; see SECURITY.md."
    )
