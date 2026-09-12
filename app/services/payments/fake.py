"""In-process payment gateway with real-gateway semantics.

Two things it models faithfully, because the saga depends on them:

1. **Idempotency.** Calling `authorize` twice with the same idempotency key
   returns the same authorization and charges once. That is what makes a retry
   after a timeout safe, and it's the property the "crash between charge and
   record" scenario relies on.
2. **Timeouts as a distinct outcome.** A timeout is not a decline. The first
   call with a `...0119` token raises PaymentTimeout; the retry — same key —
   succeeds and returns the *same* provider reference.

Swapping this for Stripe test mode is a single class: the saga only knows the
PaymentGateway protocol.
"""

import asyncio
import uuid
from decimal import Decimal

from app.services.demo_triggers import DECLINE_CODES, Trigger, trigger_for
from app.services.payments.base import AuthorizationResult, PaymentTimeout, RefundFailed


class FakePaymentGateway:
    name = "fake"

    def __init__(self, latency_seconds: float = 0.0) -> None:
        # Keyed by idempotency key: this is the gateway's own dedupe table.
        self._authorizations: dict[str, AuthorizationResult] = {}
        self._timed_out_once: set[str] = set()
        self._captured: set[str] = set()
        self._voided: set[str] = set()
        self._refunded: set[str] = set()
        # Armed by the saga when the card token asks for a refund failure, so
        # the "compensation itself fails" branch is reachable in a demo.
        self._refund_failures: set[str] = set()
        self._latency = latency_seconds

    async def _delay(self) -> None:
        if self._latency:
            await asyncio.sleep(self._latency)

    async def authorize(
        self,
        *,
        card_token: str,
        amount: Decimal,
        currency: str,
        idempotency_key: str,
        metadata: dict[str, str] | None = None,
    ) -> AuthorizationResult:
        await self._delay()

        # Replay: the defining property of an idempotent gateway.
        if idempotency_key in self._authorizations:
            return self._authorizations[idempotency_key]

        trigger = trigger_for(card_token)

        if trigger is Trigger.GATEWAY_TIMEOUT_THEN_OK and idempotency_key not in (
            self._timed_out_once
        ):
            # The dangerous case: we may or may not have charged. The saga must
            # retry with the same key, not give up and not re-charge blindly.
            self._timed_out_once.add(idempotency_key)
            raise PaymentTimeout("gateway did not respond within the deadline")

        if trigger in DECLINE_CODES:
            result = AuthorizationResult(
                provider_ref=f"auth_{uuid.uuid4().hex[:16]}",
                approved=False,
                failure_code=DECLINE_CODES[trigger],
                message=f"card declined ({DECLINE_CODES[trigger]})",
            )
        else:
            result = AuthorizationResult(
                provider_ref=f"auth_{uuid.uuid4().hex[:16]}",
                approved=True,
                message=f"authorized {amount} {currency}",
            )

        self._authorizations[idempotency_key] = result
        return result

    async def capture(self, *, provider_ref: str, idempotency_key: str) -> AuthorizationResult:
        await self._delay()
        self._captured.add(provider_ref)
        return AuthorizationResult(provider_ref=provider_ref, approved=True, message="captured")

    async def void(self, *, provider_ref: str, idempotency_key: str) -> None:
        await self._delay()
        self._voided.add(provider_ref)

    async def refund(self, *, provider_ref: str, amount: Decimal, idempotency_key: str) -> None:
        await self._delay()
        if provider_ref in self._refund_failures:
            raise RefundFailed(f"refund rejected for {provider_ref}")
        self._refunded.add(provider_ref)

    def arm_refund_failure(self, provider_ref: str) -> None:
        self._refund_failures.add(provider_ref)

    # --- test/demo introspection -------------------------------------------

    def was_voided(self, provider_ref: str) -> bool:
        return provider_ref in self._voided

    def was_refunded(self, provider_ref: str) -> bool:
        return provider_ref in self._refunded

    def authorization_count(self) -> int:
        return len(self._authorizations)

    def reset(self) -> None:
        self._authorizations.clear()
        self._timed_out_once.clear()
        self._captured.clear()
        self._voided.clear()
        self._refunded.clear()
        self._refund_failures.clear()
