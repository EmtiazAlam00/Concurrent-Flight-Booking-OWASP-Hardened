"""JWT access tokens + rotating refresh tokens with reuse detection.

The refresh design is the interesting half. Tokens form a *family*: logging in
starts a family, and each rotation marks the parent used and issues a child.
Presenting a token whose `used_at` is already set means one of two things —
someone stole it, or a client is buggy — and we cannot tell which. So we assume
theft and revoke the entire family, forcing a fresh login. The legitimate user
is inconvenienced once; the attacker loses the session entirely.
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from fastapi import Request
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db import rows_affected
from app.domain.enums import SecurityEventType, Severity
from app.domain.models import RefreshToken, User
from app.errors import InvalidToken, TokenReuseDetected
from app.security.events import client_ip, record_security_event, record_security_event_bg
from app.security.hashing import new_opaque_token, sha256_hex


def _now() -> datetime:
    return datetime.now(UTC)


# --- access tokens ----------------------------------------------------------


def create_access_token(user: User) -> tuple[str, int]:
    """Returns (token, expires_in_seconds)."""
    ttl = settings.access_token_ttl_seconds
    now = _now()
    claims = {
        "sub": str(user.id),
        "email": user.email,
        "scopes": ["admin"] if user.is_admin else ["user"],
        "typ": "access",
        "jti": str(uuid.uuid4()),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl)).timestamp()),
        "iss": "skylock",
        "aud": "skylock-api",
    }
    token = jwt.encode(claims, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, ttl


def decode_access_token(token: str) -> dict[str, Any]:
    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],  # never accept alg from the header
            audience="skylock-api",
            issuer="skylock",
            options={"require": ["exp", "iat", "sub", "typ"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise InvalidToken("Access token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise InvalidToken("Access token is not valid") from exc

    # A refresh token must never be accepted as an access token.
    if claims.get("typ") != "access":
        raise InvalidToken("Wrong token type")
    return claims


# --- refresh tokens ---------------------------------------------------------


async def issue_refresh_token(
    session: AsyncSession,
    user: User,
    *,
    request: Request | None = None,
    family_id: uuid.UUID | None = None,
    parent_id: uuid.UUID | None = None,
) -> str:
    raw = new_opaque_token(32)
    row = RefreshToken(
        family_id=family_id or uuid.uuid4(),
        user_id=user.id,
        token_hash=sha256_hex(raw),  # only the hash is persisted
        parent_id=parent_id,
        expires_at=_now() + timedelta(seconds=settings.refresh_token_ttl_seconds),
        user_agent=(request.headers.get("user-agent", "")[:400] or None) if request else None,
        ip=client_ip(request),
    )
    session.add(row)
    await session.flush()
    return raw


async def revoke_family(session: AsyncSession, family_id: uuid.UUID, reason: str) -> int:
    result = await session.execute(
        update(RefreshToken)
        .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=_now(), revoked_reason=reason)
    )
    return rows_affected(result)


async def rotate_refresh_token(
    session: AsyncSession, raw_token: str, *, request: Request | None = None
) -> tuple[User, str]:
    """Exchange a refresh token for a new one. Returns (user, new_raw_token)."""
    token_hash = sha256_hex(raw_token)
    row = await session.scalar(select(RefreshToken).where(RefreshToken.token_hash == token_hash))

    if row is None:
        # Unknown token: either forged, or from a family we already purged.
        await record_security_event_bg(
            request,
            SecurityEventType.REFRESH_REJECTED,
            Severity.MEDIUM,
            detail={"reason": "unknown_token"},
        )
        raise InvalidToken("Refresh token is not valid")

    if row.revoked_at is not None:
        await record_security_event_bg(
            request,
            SecurityEventType.REFRESH_REJECTED,
            Severity.MEDIUM,
            actor_user_id=row.user_id,
            detail={"reason": "revoked", "revoked_reason": row.revoked_reason},
        )
        raise InvalidToken("Refresh token has been revoked")

    if row.used_at is not None:
        # *** Reuse detection. *** This token was already exchanged, so either
        # it leaked or the client replayed it. We cannot distinguish the two,
        # so we treat it as theft and kill the whole family.
        revoked = await revoke_family(session, row.family_id, reason="reuse_detected")
        await record_security_event(
            session,
            SecurityEventType.REFRESH_REUSE_DETECTED,
            Severity.HIGH,
            request=request,
            actor_user_id=row.user_id,
            resource_type="refresh_family",
            resource_id=str(row.family_id),
            decision="revoke_family",
            detail={
                "family_id": str(row.family_id),
                "tokens_revoked": revoked,
                "originally_used_at": row.used_at.isoformat(),
                "note": "token presented a second time; family revoked",
            },
        )
        await session.commit()
        raise TokenReuseDetected(
            "This refresh token was already used. For your safety, all sessions "
            "in this family have been revoked — please sign in again."
        )

    if row.expires_at <= _now():
        await record_security_event_bg(
            request,
            SecurityEventType.REFRESH_REJECTED,
            Severity.LOW,
            actor_user_id=row.user_id,
            detail={"reason": "expired"},
        )
        raise InvalidToken("Refresh token has expired")

    user = await session.get(User, row.user_id)
    if user is None or not user.is_active:
        raise InvalidToken("Account is not active")

    row.used_at = _now()
    new_raw = await issue_refresh_token(
        session, user, request=request, family_id=row.family_id, parent_id=row.id
    )
    await record_security_event(
        session,
        SecurityEventType.REFRESH_ROTATED,
        Severity.INFO,
        request=request,
        actor_user_id=user.id,
        resource_type="refresh_family",
        resource_id=str(row.family_id),
        detail={"family_id": str(row.family_id)},
    )
    return user, new_raw
