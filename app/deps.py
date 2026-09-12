import uuid
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.domain.models import User
from app.errors import Forbidden, InvalidToken
from app.security.tokens import decode_access_token

DbSession = Annotated[AsyncSession, Depends(get_db)]

_bearer = HTTPBearer(auto_error=False, description="Access token from POST /auth/login")


async def current_user(
    request: Request,
    db: DbSession,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None,
) -> User:
    if credentials is None or not credentials.credentials:
        raise InvalidToken("Missing bearer token")

    claims = decode_access_token(credentials.credentials)
    try:
        user_id = uuid.UUID(claims["sub"])
    except (KeyError, ValueError) as exc:
        raise InvalidToken("Malformed subject claim") from exc

    user = await db.get(User, user_id)
    # A token can outlive the account it names; always confirm against the
    # database rather than trusting the signature alone.
    if user is None or not user.is_active:
        raise InvalidToken("Account is not active")

    request.state.user_id = str(user.id)
    request.state.user_email = user.email
    return user


CurrentUser = Annotated[User, Depends(current_user)]


async def require_admin(user: CurrentUser) -> User:
    if not user.is_admin:
        from app.domain.enums import SecurityEventType, Severity
        from app.security.events import record_security_event_bg

        await record_security_event_bg(
            None,
            SecurityEventType.AUTHZ_DENIED,
            Severity.MEDIUM,
            actor_user_id=user.id,
            decision="deny",
            detail={"reason": "admin_scope_required"},
        )
        raise Forbidden("Administrator scope required")
    return user


AdminUser = Annotated[User, Depends(require_admin)]
