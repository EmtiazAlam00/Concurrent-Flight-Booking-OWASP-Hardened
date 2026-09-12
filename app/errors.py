"""RFC 9457 problem+json errors with stable machine-readable codes.

Every error the API can return has a `code` that clients (and tests) match on.
Human-readable `detail` may change; `code` does not.
"""

from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

PROBLEM_JSON = "application/problem+json"


class AppError(Exception):
    status_code: int = status.HTTP_400_BAD_REQUEST
    code: str = "bad_request"
    title: str = "Bad request"

    def __init__(self, detail: str | None = None, **extra: Any) -> None:
        self.detail = detail or self.title
        self.extra = extra
        super().__init__(self.detail)

    def to_problem(self, instance: str) -> dict[str, Any]:
        body: dict[str, Any] = {
            "type": f"https://skylock.dev/problems/{self.code}",
            "title": self.title,
            "status": self.status_code,
            "detail": self.detail,
            "code": self.code,
            "instance": instance,
        }
        body.update(self.extra)
        return body


# --- auth -------------------------------------------------------------------


class InvalidCredentials(AppError):
    status_code = status.HTTP_401_UNAUTHORIZED
    code = "invalid_credentials"
    title = "Invalid email or password"


class AccountLocked(AppError):
    status_code = status.HTTP_423_LOCKED
    code = "account_locked"
    title = "Account temporarily locked"


class InvalidToken(AppError):
    status_code = status.HTTP_401_UNAUTHORIZED
    code = "invalid_token"
    title = "Invalid or expired token"


class TokenReuseDetected(AppError):
    status_code = status.HTTP_401_UNAUTHORIZED
    code = "token_reuse_detected"
    title = "Refresh token replay detected; session family revoked"


class EmailAlreadyRegistered(AppError):
    status_code = status.HTTP_409_CONFLICT
    code = "email_already_registered"
    title = "Email already registered"


class Forbidden(AppError):
    status_code = status.HTTP_403_FORBIDDEN
    code = "forbidden"
    title = "Forbidden"


# --- resources --------------------------------------------------------------


class NotFound(AppError):
    status_code = status.HTTP_404_NOT_FOUND
    code = "not_found"
    title = "Resource not found"


# --- inventory / holds ------------------------------------------------------


class SeatUnavailable(AppError):
    status_code = status.HTTP_409_CONFLICT
    code = "seat_unavailable"
    title = "Seat is not available"


class HoldExpired(AppError):
    status_code = status.HTTP_409_CONFLICT
    code = "hold_expired"
    title = "Seat hold has expired"


class HoldNotOwned(AppError):
    status_code = status.HTTP_404_NOT_FOUND
    code = "not_found"
    title = "Resource not found"


class TooManyHolds(AppError):
    status_code = status.HTTP_409_CONFLICT
    code = "too_many_holds"
    title = "Too many active seat holds"


# --- booking saga -----------------------------------------------------------


class PaymentDeclined(AppError):
    status_code = status.HTTP_402_PAYMENT_REQUIRED
    code = "payment_declined"
    title = "Payment was declined"


class BookingCompensated(AppError):
    """Charge succeeded but the booking could not be completed; money returned."""

    status_code = status.HTTP_409_CONFLICT
    code = "booking_compensated"
    title = "Booking could not be completed and was reversed"


class RequestInFlight(AppError):
    status_code = status.HTTP_409_CONFLICT
    code = "request_in_flight"
    title = "An identical request is still being processed"


class IdempotencyKeyReused(AppError):
    # 422 literal: Starlette renamed the constant, and the number is the
    # stable part of the contract.
    status_code = 422
    code = "idempotency_key_reused"
    title = "Idempotency key was reused with a different request body"


class InvalidStateTransition(AppError):
    status_code = status.HTTP_409_CONFLICT
    code = "invalid_state_transition"
    title = "Operation not allowed in the booking's current state"


# --- abuse controls ---------------------------------------------------------


class RateLimited(AppError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    code = "rate_limited"
    title = "Too many requests"

    def __init__(self, detail: str | None = None, retry_after: int = 60, **extra: Any) -> None:
        self.retry_after = retry_after
        super().__init__(detail, retry_after=retry_after, **extra)


class PaymentBlocked(AppError):
    status_code = status.HTTP_403_FORBIDDEN
    code = "payment_blocked"
    title = "Payment blocked by fraud controls"


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(request: Request, exc: AppError) -> JSONResponse:
        headers = {}
        if isinstance(exc, RateLimited):
            headers["Retry-After"] = str(exc.retry_after)
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.to_problem(str(request.url.path)),
            media_type=PROBLEM_JSON,
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Strict validation is an injection defense, so a rejection is worth a
        # line in the security log — but only the shape of the failure, never
        # the offending value (it may be a credential).
        from app.domain.enums import SecurityEventType, Severity
        from app.security.events import record_security_event_bg

        fields = [".".join(str(p) for p in e["loc"][1:]) for e in exc.errors()]
        await record_security_event_bg(
            request,
            SecurityEventType.VALIDATION_REJECTED,
            Severity.INFO,
            detail={"fields": fields[:20], "error_count": len(exc.errors())},
        )
        return JSONResponse(
            status_code=422,
            content={
                "type": "https://skylock.dev/problems/validation_failed",
                "title": "Request validation failed",
                "status": 422,
                "code": "validation_failed",
                "instance": str(request.url.path),
                "errors": [
                    {"field": ".".join(str(p) for p in e["loc"][1:]), "message": e["msg"]}
                    for e in exc.errors()
                ],
            },
            media_type=PROBLEM_JSON,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "type": "about:blank",
                "title": str(exc.detail),
                "status": exc.status_code,
                "code": "http_error",
                "instance": str(request.url.path),
            },
            media_type=PROBLEM_JSON,
            headers=getattr(exc, "headers", None),
        )
