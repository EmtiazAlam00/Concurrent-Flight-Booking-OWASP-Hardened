"""Idempotency keys, stored in Postgres.

Three cases a correct implementation has to separate, and the third is the one
most implementations miss:

1. **Same key, same body, finished** -> replay the stored response byte for
   byte, including the original status code. A retried booking returns the
   original 201, not a second booking.
2. **Same key, same body, still running** -> 409 with Retry-After. Do not start
   the saga twice; that is exactly the double-charge we're preventing.
3. **Same key, *different* body** -> 422. This is a client bug (a key got
   reused across two genuinely different requests) and silently replaying the
   first response would hide it. Surfacing it is the difference between an
   idempotency key and a cache key.

Errors are recorded too: a retried request that was declined gets the same 402
back rather than being re-charged.
"""

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.domain.enums import IdempotencyState
from app.domain.models import IdempotencyKey
from app.errors import IdempotencyKeyReused, RequestInFlight


@dataclass(frozen=True)
class Replay:
    """A previously completed response for this key."""

    status_code: int
    body: dict[str, Any]


def request_hash(payload: Any) -> str:
    """Stable hash of the request body.

    Canonicalized (sorted keys, no whitespace) so that a semantically identical
    retry hashes the same even if the client's serializer reorders fields.
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


async def begin(
    session: AsyncSession,
    *,
    key: str,
    user_id: uuid.UUID,
    endpoint: str,
    payload: Any,
) -> Replay | None:
    """Claim `key` for this request.

    Returns None if we now own the claim and should do the work, or a Replay to
    return to the client instead. Commits, so concurrent duplicates see the
    IN_PROGRESS row immediately.
    """
    digest = request_hash(payload)
    now = datetime.now(UTC)

    # Clear an expired claim for this key so it can be reused legitimately.
    await session.execute(
        delete(IdempotencyKey).where(
            IdempotencyKey.key == key,
            IdempotencyKey.user_id == user_id,
            IdempotencyKey.expires_at < now,
        )
    )

    stmt = (
        pg_insert(IdempotencyKey)
        .values(
            key=key,
            user_id=user_id,
            endpoint=endpoint,
            request_hash=digest,
            state=IdempotencyState.IN_PROGRESS,
            expires_at=now + timedelta(seconds=settings.idempotency_ttl_seconds),
        )
        .on_conflict_do_nothing(index_elements=["key", "user_id"])
        .returning(IdempotencyKey.key)
    )
    claimed = (await session.execute(stmt)).scalar_one_or_none()
    await session.commit()

    if claimed is not None:
        return None  # we own it; run the work

    existing = await session.scalar(
        select(IdempotencyKey).where(IdempotencyKey.key == key, IdempotencyKey.user_id == user_id)
    )
    if existing is None:
        # Raced with a cleanup between the INSERT and the SELECT. Treat as busy;
        # the client's retry will claim it cleanly.
        raise RequestInFlight("Please retry in a moment")

    if existing.request_hash != digest:
        raise IdempotencyKeyReused(
            "This Idempotency-Key was already used for a different request body. "
            "Use a fresh key for a new request."
        )

    if existing.state == IdempotencyState.COMPLETED and existing.response_status:
        return Replay(existing.response_status, existing.response_body or {})

    raise RequestInFlight("An identical request is still being processed; retry shortly.")


async def complete(
    session: AsyncSession,
    *,
    key: str,
    user_id: uuid.UUID,
    status_code: int,
    body: dict[str, Any],
    booking_id: uuid.UUID | None = None,
) -> None:
    record = await session.scalar(
        select(IdempotencyKey).where(IdempotencyKey.key == key, IdempotencyKey.user_id == user_id)
    )
    if record is None:
        return
    record.state = IdempotencyState.COMPLETED
    record.response_status = status_code
    record.response_body = body
    record.booking_id = booking_id
    await session.commit()


async def release(session: AsyncSession, *, key: str, user_id: uuid.UUID) -> None:
    """Drop the claim so the client can safely retry.

    Used only for *unexpected* failures, where we don't know enough to record a
    response. A known outcome (declined, conflict) is recorded via complete()
    so the retry replays it instead of re-running the saga.
    """
    await session.execute(
        delete(IdempotencyKey).where(IdempotencyKey.key == key, IdempotencyKey.user_id == user_id)
    )
    await session.commit()
