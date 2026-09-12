from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.config import settings
from app.deps import CurrentUser, DbSession
from app.domain.enums import SecurityEventType, Severity
from app.domain.models import RefreshToken, User
from app.errors import AccountLocked, EmailAlreadyRegistered, InvalidCredentials
from app.schemas.auth import (
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.security.events import record_security_event
from app.security.hashing import hash_password, normalize_email, sha256_hex, verify_password
from app.security.ratelimit import rate_limit
from app.security.tokens import (
    create_access_token,
    issue_refresh_token,
    revoke_family,
    rotate_refresh_token,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit("register"))],
)
async def register(payload: RegisterRequest, request: Request, db: DbSession) -> TokenResponse:
    email = normalize_email(payload.email)
    user = User(
        email=email,
        password_hash=hash_password(payload.password),
        full_name=payload.full_name,
    )
    db.add(user)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise EmailAlreadyRegistered("An account with this email already exists") from exc

    access, expires_in = create_access_token(user)
    refresh = await issue_refresh_token(db, user, request=request)
    await record_security_event(
        db,
        SecurityEventType.REGISTERED,
        Severity.INFO,
        request=request,
        actor_user_id=user.id,
        actor_email=email,
    )
    await db.commit()
    return TokenResponse(access_token=access, refresh_token=refresh, expires_in=expires_in)


@router.post(
    "/login",
    response_model=TokenResponse,
    dependencies=[Depends(rate_limit("login"))],
)
async def login(payload: LoginRequest, request: Request, db: DbSession) -> TokenResponse:
    """Password login with per-account lockout.

    Two deliberate properties:

    * The same 401 is returned whether the email is unknown or the password is
      wrong, and `verify_password` burns equivalent CPU on a miss — so this
      endpoint is not a user-enumeration oracle.
    * Lockout is on the account, and the rate limiter (above) is on the IP, so
      neither a single-account brute force nor a spray across many accounts gets
      an unbounded number of guesses.
    """
    email = normalize_email(payload.email)
    user = await db.scalar(select(User).where(User.email == email))
    now = datetime.now(UTC)

    if user is not None and user.locked_until is not None and user.locked_until > now:
        await record_security_event(
            db,
            SecurityEventType.LOGIN_FAILED,
            Severity.MEDIUM,
            request=request,
            actor_user_id=user.id,
            actor_email=email,
            decision="deny",
            detail={"reason": "account_locked", "locked_until": user.locked_until.isoformat()},
        )
        await db.commit()
        raise AccountLocked(
            "Too many failed attempts. Try again after "
            f"{user.locked_until.isoformat(timespec='seconds')}."
        )

    if not verify_password(payload.password, user.password_hash if user else None):
        if user is not None:
            user.failed_login_count += 1
            locked = user.failed_login_count >= settings.login_max_failures
            if locked:
                user.locked_until = now + timedelta(seconds=settings.login_lockout_seconds)
                user.failed_login_count = 0
            await record_security_event(
                db,
                SecurityEventType.ACCOUNT_LOCKED if locked else SecurityEventType.LOGIN_FAILED,
                Severity.HIGH if locked else Severity.LOW,
                request=request,
                actor_user_id=user.id,
                actor_email=email,
                decision="deny",
                detail={
                    "reason": "bad_password",
                    "failed_count": user.failed_login_count,
                    "locked": locked,
                },
            )
        else:
            await record_security_event(
                db,
                SecurityEventType.LOGIN_FAILED,
                Severity.LOW,
                request=request,
                actor_email=email,
                decision="deny",
                detail={"reason": "unknown_account"},
            )
        await db.commit()
        raise InvalidCredentials("Invalid email or password")

    assert user is not None
    user.failed_login_count = 0
    user.locked_until = None

    access, expires_in = create_access_token(user)
    refresh = await issue_refresh_token(db, user, request=request)
    await record_security_event(
        db,
        SecurityEventType.LOGIN_SUCCEEDED,
        Severity.INFO,
        request=request,
        actor_user_id=user.id,
        actor_email=email,
    )
    await db.commit()
    return TokenResponse(access_token=access, refresh_token=refresh, expires_in=expires_in)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    dependencies=[Depends(rate_limit("refresh"))],
)
async def refresh_tokens(payload: RefreshRequest, request: Request, db: DbSession) -> TokenResponse:
    """Rotate a refresh token.

    Replaying an already-rotated token revokes the entire family — see
    app/security/tokens.py for why that is the right response to an
    indistinguishable theft-or-bug signal.
    """
    user, new_refresh = await rotate_refresh_token(db, payload.refresh_token, request=request)
    access, expires_in = create_access_token(user)
    await db.commit()
    return TokenResponse(access_token=access, refresh_token=new_refresh, expires_in=expires_in)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(payload: RefreshRequest, request: Request, db: DbSession) -> None:
    """Revoke the whole family, not just the presented token.

    Revoking one token would leave any already-rotated sibling usable, which
    defeats the point of logging out on a shared machine.
    """
    row = await db.scalar(
        select(RefreshToken).where(RefreshToken.token_hash == sha256_hex(payload.refresh_token))
    )
    if row is not None:
        await revoke_family(db, row.family_id, reason="logout")
        await db.commit()
    # Always 204: whether the token existed is not the caller's business.


@router.get("/me", response_model=UserResponse)
async def me(user: CurrentUser) -> User:
    return user
