"""Best-effort auth context, attached to every request before routing.

Why this exists: rate limiting and security-event logging both want to know
*who* is calling, including on requests that are about to be rejected. Relying
on the `current_user` dependency for that doesn't work — FastAPI resolves
route-level dependencies before endpoint parameters, so a rate limiter would run
before the user was known.

This middleware only *decodes* the token; it performs no database lookup and
grants no authority. Authorization still happens in `app.deps.current_user`,
which verifies the user exists and is active. Nothing here may be used to make
an access-control decision.
"""

from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.security.tokens import decode_access_token


class AuthContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request.state.user_id = None
        request.state.user_email = None

        header = request.headers.get("authorization", "")
        if header.lower().startswith("bearer "):
            try:
                claims = decode_access_token(header[7:].strip())
                request.state.user_id = claims.get("sub")
                request.state.user_email = claims.get("email")
            except Exception:  # noqa: BLE001, S110
                # An invalid or expired token simply means "no context". This is
                # deliberately silent: every unauthenticated request would log,
                # and the token material must never reach the logs. The real
                # rejection happens (and is logged) in deps.current_user.
                pass

        return await call_next(request)
